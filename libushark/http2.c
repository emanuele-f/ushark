/*
 * HTTP/2 module for ushark
 * Copyright 2024 Emanuele Faranda
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * ushark - brings the Wireshark dissection to Nodejs apps
 * Copyright 2022-23 AltaFinance
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdlib.h>
#include <stdbool.h>
#include <epan/tvbuff.h>
#include <epan/packet_info.h>
#include <epan/proto.h>
#include <epan/dissectors/packet-http2.h>

#include "http2.h"

struct ushark_http2_ctx {
  GHashTable* reassembly_hash;
};

typedef struct {
    char *method;
    char *authority;
    char *scheme;
    char *path;
    char *status;

    char *buf;
    size_t buflen;
} http2_headers_t;

typedef struct {
    http2_headers_t http2_hdrs;

    char *headers_buf;
    size_t headers_buflen;

    const guint8* body_buf;       // unmanaged
    size_t body_buflen;

    bool end_stream;
} http2_reassembly_t;

typedef enum {
    HTTP2_LVL_ROOT = 0,           // http2
    HTTP2_LVL_STREAM = 1,         // http2.stream
    HTTP2_LVL_HEADERS_BODY = 2,   // http2.header / http2.body.fragments
} http2_search_lvl;

typedef struct {
    // http2 -> http2.stream -> http2.header / http2.body.fragments
    http2_search_lvl cur_lvl;
    http2_reassembly_t *results;
} http2_tree_search_t;

typedef struct {
    proto_node *header_name;
    proto_node *header_value;
} http2_hdr_info;

static void free_http2_reassembly(http2_reassembly_t *res) {
    if (res->http2_hdrs.method)
        free(res->http2_hdrs.method);
    if (res->http2_hdrs.authority)
        free(res->http2_hdrs.authority);
    if (res->http2_hdrs.scheme)
        free(res->http2_hdrs.scheme);
    if (res->http2_hdrs.path)
        free(res->http2_hdrs.path);
    if (res->http2_hdrs.status)
        free(res->http2_hdrs.status);
    if (res->http2_hdrs.buf)
        free(res->http2_hdrs.buf);

    if (res->headers_buf)
        free(res->headers_buf);

    free(res);
}

static void
extract_http2_reassembled_body(proto_node *pn, gpointer data)
{
    proto_node **node = (proto_node**) data;
    const char *node_key = pn->finfo->hfinfo->abbrev;

    if (strcmp(node_key, "http2.body.reassembled.data") == 0)
        *node = pn;
}

static void
extract_http2_header(proto_node *pn, gpointer data)
{
    http2_hdr_info* hinfo = (http2_hdr_info*) data;
    const char *node_key = pn->finfo->hfinfo->abbrev;

    if (strcmp(node_key, "http2.header.name") == 0)
        hinfo->header_name = pn;
    else if (strcmp(node_key, "http2.header.value") == 0)
        hinfo->header_value = pn;
}

static void
search_http2_data(proto_node *pn, gpointer data)
{
    http2_tree_search_t* ts = (http2_tree_search_t*) data;
    if (ts->cur_lvl > HTTP2_LVL_HEADERS_BODY)
        return;

    http2_reassembly_t *res = ts->results;
    const char *node_key = pn->finfo->hfinfo->abbrev;

    bool go_deeper = false;

    if (ts->cur_lvl == HTTP2_LVL_ROOT)
        go_deeper = (strcmp(node_key, "http2") == 0);
    else if (ts->cur_lvl == HTTP2_LVL_STREAM) {
        go_deeper = (strcmp(node_key, "http2.stream") == 0);
    } else { // HTTP2_LVL_HEADERS_BODY
        if (strcmp(node_key, "http2.header") == 0) {
            http2_hdr_info hinfo = {};
            proto_tree_children_foreach(pn, extract_http2_header, &hinfo);

            if (hinfo.header_name && hinfo.header_value) {
                field_info *name_finfo = hinfo.header_name->finfo;
                field_info *val_finfo = hinfo.header_value->finfo;

                const guint8 *name_ptr = tvb_get_ptr(name_finfo->ds_tvb, name_finfo->start, name_finfo->length);
                const guint8 *val_ptr = tvb_get_ptr(val_finfo->ds_tvb, val_finfo->start, val_finfo->length);

                if (name_ptr && val_ptr && *name_ptr) {
                    size_t tot_len = name_finfo->length + 2 /*": "*/ + val_finfo->length + 2 /* \r\n */;
                    char **buf_ptr = NULL;
                    size_t *len_ptr;

                    if (*name_ptr == ':') {
                        // HTTP/2 headers
                        const char* name_ptr_c =  (const char*) name_ptr;
                        const char* val_ptr_c =  (const char*) val_ptr;

                        if (!res->http2_hdrs.method && strcmp(name_ptr_c, ":method") == 0)
                            res->http2_hdrs.method = strndup(val_ptr_c, val_finfo->length);
                        else if (!res->http2_hdrs.authority && strcmp(name_ptr_c, ":authority") == 0)
                            res->http2_hdrs.authority = strndup(val_ptr_c, val_finfo->length);
                        else if (!res->http2_hdrs.scheme && strcmp(name_ptr_c, ":scheme") == 0)
                            res->http2_hdrs.scheme = strndup(val_ptr_c, val_finfo->length);
                        else if (!res->http2_hdrs.path && strcmp(name_ptr_c, ":path") == 0)
                            res->http2_hdrs.path = strndup(val_ptr_c, val_finfo->length);
                        else if (!res->http2_hdrs.status && strcmp(name_ptr_c, ":status") == 0)
                            res->http2_hdrs.status = strndup(val_ptr_c, val_finfo->length);

                        buf_ptr = &res->http2_hdrs.buf;
                        len_ptr = &res->http2_hdrs.buflen;
                    } else {
                        // HTTP headers
                        buf_ptr = &res->headers_buf;
                        len_ptr = &res->headers_buflen;
                    }

                    *buf_ptr = realloc(*buf_ptr, *len_ptr + tot_len);
                    guint8 *p = (guint8*) *buf_ptr + *len_ptr;
                    memcpy(p, name_ptr, name_finfo->length); p += name_finfo->length;
                    *p++ = ':';
                    *p++ = ' ';
                    memcpy(p, val_ptr, val_finfo->length); p += val_finfo->length;
                    *p++ = '\r';
                    *p++ = '\n';
                    *len_ptr += tot_len;
                }
            }
        } else if (!res->body_buf && (strcmp(node_key, "http2.body.fragments") == 0)) {
            proto_node *reassembled_body = NULL;

            proto_tree_children_foreach(pn, extract_http2_reassembled_body, &reassembled_body);
            if (reassembled_body) {
                field_info *finfo = reassembled_body->finfo;
                const guint8 *body_ptr = tvb_get_ptr(finfo->ds_tvb, finfo->start, finfo->length);

                if (body_ptr) {
                    res->body_buf = body_ptr;
                    res->body_buflen = finfo->length;
                }
            }
        } else if (!res->end_stream && (strcmp(node_key, "http2.flags") == 0)) {
            uint8_t flags = fvalue_get_uinteger(&pn->finfo->value);

            if (flags & 0x01) // HTTP2_FLAGS_END_STREAM
                res->end_stream = 1;
        }
    }

    if (go_deeper) {
        http2_tree_search_t deeper = *ts;
        deeper.cur_lvl++;
        proto_tree_children_foreach(pn, search_http2_data, &deeper);
    }
}

ushark_http2_ctx_t* ushark_http2_init() {
  ushark_http2_ctx_t *ctx = (ushark_http2_ctx_t*) calloc(1, sizeof(ushark_http2_ctx_t));

  ctx->reassembly_hash = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)free_http2_reassembly);

  return ctx;
}

void ushark_http2_cleanup(ushark_http2_ctx_t* ctx) {
  g_hash_table_destroy(ctx->reassembly_hash);
  free(ctx);
}

void ushark_http2_process_data(ushark_http2_ctx_t *ctx, epan_dissect_t *edt, conversation_t *conv, ushark_tls_data_callback tls_cb) {
  guint32 stream_id = http2_get_stream_id(&edt->pi);
  guint32 reassembly_key = (conv->conv_index << 10) | stream_id;  // possible collisions, but unlikely
  //printf("STREAM ID: %u.%u - %u\n", conv->conv_index, stream_id, reassembly_key);

  http2_reassembly_t *res = (http2_reassembly_t*)
      g_hash_table_lookup(ctx->reassembly_hash, GUINT_TO_POINTER(reassembly_key));

  if (!res) {
      res = calloc(1, sizeof(http2_reassembly_t));
      g_hash_table_insert(ctx->reassembly_hash, GUINT_TO_POINTER(reassembly_key), res);
  }

  http2_tree_search_t ts = {};
  ts.results = res;
  proto_tree_children_foreach(edt->tree, search_http2_data, &ts);

  // NOTE: body_buf will be invalidated on next run, so check explicitly
  if (res->body_buf || res->end_stream) {
      // Complete reassembly
      char tmp[512];
      char *pre_headers = NULL;
      size_t pre_headers_len = 0;

      if (res->http2_hdrs.buf) {
          if (res->http2_hdrs.status) {
              // HTTP reply
              pre_headers_len = snprintf(tmp, sizeof(tmp), "HTTP/2.0 %s\r\n", res->http2_hdrs.status);
              if (pre_headers_len >= sizeof(tmp))
                  pre_headers_len = sizeof(tmp) - 1;

              pre_headers = tmp;
          } else if (res->http2_hdrs.method && res->http2_hdrs.authority) {
              pre_headers_len = snprintf(tmp, sizeof(tmp), "%s %s://%s%s HTTP/2.0\r\n",
                  res->http2_hdrs.method,
                  res->http2_hdrs.scheme ? res->http2_hdrs.scheme : "http",
                  res->http2_hdrs.authority,
                  res->http2_hdrs.path ? res->http2_hdrs.path : "/");
              if (pre_headers_len >= sizeof(tmp))
                  pre_headers_len = sizeof(tmp) - 1;

              pre_headers = tmp;
          } else {
              pre_headers = res->http2_hdrs.buf;
              pre_headers_len = res->http2_hdrs.buflen;
          }
      }

      size_t tot_hdr_size = (pre_headers_len + res->headers_buflen > 0) ?
          (pre_headers_len + res->headers_buflen + 2) : 0; // \r\n
      size_t tot_size = tot_hdr_size + res->body_buflen;

      if (tot_hdr_size > 0) {
          guint8* assembly = (guint8*) malloc(tot_size);
          guint8* p = assembly;

          if (pre_headers_len > 0) {
              memcpy(p, pre_headers, pre_headers_len);
              p += pre_headers_len;
          }
          if (res->headers_buflen > 0) {
              memcpy(p, res->headers_buf, res->headers_buflen);
              p += res->headers_buflen;
          }

          *p++ = '\r';
          *p++ = '\n';

          if (res->body_buflen > 0) {
              memcpy(p, res->body_buf, res->body_buflen);
              p += res->body_buflen;
          }

          tls_cb(assembly, tot_size);
          free(assembly);
      } else if (res->body_buflen > 0)
          tls_cb(res->body_buf, res->body_buflen);

      g_hash_table_remove(ctx->reassembly_hash, GUINT_TO_POINTER(reassembly_key));
  }
}
