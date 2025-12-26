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

    const guint8* data_buf;       // unmanaged
    size_t data_buflen;

    bool end_stream;
} http2_reassembly_t;

typedef enum {
    HTTP2_LVL_ROOT = 0,           // http2
    HTTP2_LVL_STREAM = 1,         // http2.stream
    HTTP2_LVL_HEADERS_BODY = 2,   // http2.header / http2.body.fragments / http2.data.data
} http2_search_lvl;

typedef struct {
    // http2 -> http2.stream -> http2.header / http2.body.fragments / http2.data.data
    http2_search_lvl cur_lvl;
    ushark_http2_ctx_t *ctx;
    conversation_t *conv;
    http2_reassembly_t *results;
    ushark_tls_data_callback tls_cb;
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
extract_http2_stream_id(proto_node *pn, gpointer data)
{
    guint32 *stream_id = (guint32*) data;
    const char *node_key = pn->finfo->hfinfo->abbrev;

    if (strcmp(node_key, "http2.streamid") == 0) {
        *stream_id = fvalue_get_uinteger(&pn->finfo->value);
    }
}

static void output_http2_message(http2_reassembly_t *res, ushark_tls_data_callback tls_cb) {
    char *pre_headers = NULL;
    char *tmp_buf = NULL;
    size_t pre_headers_len = 0;

    if (res->http2_hdrs.buf) {
        if (res->http2_hdrs.status) {
            // HTTP reply
            int rv = asprintf(&tmp_buf, "HTTP/2.0 %s\r\n", res->http2_hdrs.status);

            if (rv > 0) {
                pre_headers_len = rv;
                pre_headers = tmp_buf;
            } else
                pre_headers_len = 0;
        } else if (res->http2_hdrs.method && res->http2_hdrs.authority) {
            int rv = asprintf(&tmp_buf, "%s %s://%s%s HTTP/2.0\r\n",
                res->http2_hdrs.method,
                res->http2_hdrs.scheme ? res->http2_hdrs.scheme : "http",
                res->http2_hdrs.authority,
                res->http2_hdrs.path ? res->http2_hdrs.path : "/");

            if (rv > 0) {
                pre_headers_len = rv;
                pre_headers = tmp_buf;
            } else
                pre_headers_len = 0;
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

    if (tmp_buf)
        free(tmp_buf);
}

static void
search_http2_data(proto_node *pn, gpointer data)
{
    http2_tree_search_t* ts = (http2_tree_search_t*) data;
    if (ts->cur_lvl > HTTP2_LVL_HEADERS_BODY)
        return;

    http2_reassembly_t *res = ts->results;
    const char *node_key = pn->finfo->hfinfo->abbrev;

    if (ts->cur_lvl == HTTP2_LVL_ROOT) {
        if (strcmp(node_key, "http2") == 0) {
            // go deeper
            ts->cur_lvl++;
            proto_tree_children_foreach(pn, search_http2_data, ts);
            ts->cur_lvl--;
        }
    } else if (ts->cur_lvl == HTTP2_LVL_STREAM) {
        if (strcmp(node_key, "http2.stream") == 0) {
            // Extract stream ID from this stream node
            guint32 stream_id = 0;
            proto_tree_children_foreach(pn, extract_http2_stream_id, &stream_id);

            if (stream_id > 0) {
                // Look up or create reassembly entry for this specific stream
                guint32 reassembly_key = (ts->conv->conv_index << 10) | stream_id;
                http2_reassembly_t *stream_res = (http2_reassembly_t*)
                    g_hash_table_lookup(ts->ctx->reassembly_hash, GUINT_TO_POINTER(reassembly_key));

                if (!stream_res) {
                    stream_res = calloc(1, sizeof(http2_reassembly_t));
                    g_hash_table_insert(ts->ctx->reassembly_hash, GUINT_TO_POINTER(reassembly_key), stream_res);
                }

                // Process this stream with its own reassembly context
                http2_tree_search_t stream_ts = *ts;
                stream_ts.results = stream_res;
                stream_ts.cur_lvl++;
                proto_tree_children_foreach(pn, search_http2_data, &stream_ts);

                // Check if stream is complete and output if needed
                if (stream_res->end_stream) {
                    if (!stream_res->body_buf) {
                        stream_res->body_buf = stream_res->data_buf;
                        stream_res->body_buflen = stream_res->data_buflen;
                    }

                    output_http2_message(stream_res, ts->tls_cb);
                    g_hash_table_remove(ts->ctx->reassembly_hash, GUINT_TO_POINTER(reassembly_key));
                } else {
                    stream_res->end_stream = false;
                }
            }
        }
    } else { // HTTP2_LVL_HEADERS_BODY
        if (res && (strcmp(node_key, "http2.header") == 0)) {
            http2_hdr_info hinfo = {};
            proto_tree_children_foreach(pn, extract_http2_header, &hinfo);

            if (hinfo.header_name && hinfo.header_value) {
                field_info *name_finfo = hinfo.header_name->finfo;
                field_info *val_finfo = hinfo.header_value->finfo;

                const guint8 *name_ptr = tvb_get_ptr(name_finfo->ds_tvb, name_finfo->start, name_finfo->length);
                const guint8 *val_ptr = tvb_get_ptr(val_finfo->ds_tvb, val_finfo->start, val_finfo->length);

                if (name_ptr && val_ptr && *name_ptr) {
                    const char* name_ptr_c = (const char*) name_ptr;

                    // Check if this is a new message (indicated by :method or :status pseudo-headers)
                    // If we already have accumulated data, output it first
                    if (*name_ptr == ':' &&
                        (strcmp(name_ptr_c, ":method") == 0 || strcmp(name_ptr_c, ":status") == 0)) {
                        if (res->http2_hdrs.buf || res->body_buflen > 0 || res->data_buflen > 0) {
                            if (!res->body_buf) {
                                res->body_buf = res->data_buf;
                                res->body_buflen = res->data_buflen;
                            }
                            output_http2_message(res, ts->tls_cb);

                            // Clear for next message
                            memset(res, 0, sizeof(http2_reassembly_t));
                        }
                    }

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
            // Multi-frame body: look for reassembled data
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
        } else if (!res->data_buf && (strcmp(node_key, "http2.data.data") == 0)) {
            // Single-frame body: use the DATA frame payload directly
            field_info *finfo = pn->finfo;
            const guint8 *body_ptr = tvb_get_ptr(finfo->ds_tvb, finfo->start, finfo->length);

            // NOTE: using a separate field from body_buf to avoid duplicating or having
            // partial data when both fragments and non-fragments data are present
            if (body_ptr) {
                res->data_buf = body_ptr;
                res->data_buflen = finfo->length;
            }
        } else if ((strcmp(node_key, "http2.flags") == 0)) {
            uint8_t flags = fvalue_get_uinteger(&pn->finfo->value);

            if (flags & 0x01) // HTTP2_FLAGS_END_STREAM
                res->end_stream = 1;
        }
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
  // Initialize tree search context
  http2_tree_search_t ts = {};
  ts.tls_cb = tls_cb;
  ts.ctx = ctx;
  ts.conv = conv;
  ts.results = NULL;  // Will be set per-stream during traversal

  proto_tree_children_foreach(edt->tree, search_http2_data, &ts);
}
