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

    guint8* body_buf;             // managed - allocated memory
    size_t body_buflen;

    guint8* data_buf;             // managed - allocated memory
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
    const ushark_data_callbacks_t *cbs;
} http2_tree_search_t;

typedef struct {
    proto_node *header_name;
    proto_node *header_value;
} http2_hdr_info;

typedef struct {
    guint32 stream_id;
    guint32 frame_type;
} http2_stream_info_t;

typedef struct {
    guint32 conv_index;
    guint32 stream_id;
} http2_reassembly_key_t;

static guint http2_reassembly_key_hash(gconstpointer v) {
    const http2_reassembly_key_t *key = (const http2_reassembly_key_t*)v;
    return key->conv_index ^ key->stream_id;
}

static gboolean http2_reassembly_key_equal(gconstpointer v1, gconstpointer v2) {
    const http2_reassembly_key_t *key1 = (const http2_reassembly_key_t*)v1;
    const http2_reassembly_key_t *key2 = (const http2_reassembly_key_t*)v2;
    return key1->conv_index == key2->conv_index && key1->stream_id == key2->stream_id;
}

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

    // Free managed body buffers
    if (res->body_buf)
        g_free(res->body_buf);
    if (res->data_buf)
        g_free(res->data_buf);

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
extract_http2_stream_info(proto_node *pn, gpointer data)
{
    http2_stream_info_t *info = (http2_stream_info_t*) data;
    const char *node_key = pn->finfo->hfinfo->abbrev;

    if (strcmp(node_key, "http2.streamid") == 0) {
        info->stream_id = fvalue_get_uinteger(&pn->finfo->value);
    } else if (strcmp(node_key, "http2.type") == 0) {
        info->frame_type = fvalue_get_uinteger(&pn->finfo->value);
    }
}

// Returns a newly allocated buffer containing the reassembled HTTP/2 message.
// The caller is responsible for freeing the returned buffer with free().
// Returns NULL if there's no data to return.
// The size of the buffer is written to *out_size.
static unsigned char* reassemble_http2_message(http2_reassembly_t *res, size_t *out_size) {
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
            } else {
                pre_headers_len = 0;
                tmp_buf = NULL;
            }
        } else if (res->http2_hdrs.method && res->http2_hdrs.authority) {
            int rv = asprintf(&tmp_buf, "%s %s://%s%s HTTP/2.0\r\n",
                res->http2_hdrs.method,
                res->http2_hdrs.scheme ? res->http2_hdrs.scheme : "http",
                res->http2_hdrs.authority,
                res->http2_hdrs.path ? res->http2_hdrs.path : "/");

            if (rv > 0) {
                pre_headers_len = rv;
                pre_headers = tmp_buf;
            } else {
                pre_headers_len = 0;
                tmp_buf = NULL;
            }
        } else {
            pre_headers = res->http2_hdrs.buf;
            pre_headers_len = res->http2_hdrs.buflen;
        }
    }

    size_t tot_hdr_size = (pre_headers_len + res->headers_buflen > 0) ?
        (pre_headers_len + res->headers_buflen + 2) : 0; // \r\n
    size_t tot_size = tot_hdr_size + res->body_buflen;

    unsigned char* assembly = NULL;

    if (tot_hdr_size > 0) {
        assembly = (unsigned char*) malloc(tot_size);
        unsigned char* p = assembly;

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

        *out_size = tot_size;
    } else if (res->body_buflen > 0) {
        // Only body, no headers
        assembly = (unsigned char*) malloc(res->body_buflen);
        memcpy(assembly, res->body_buf, res->body_buflen);
        *out_size = res->body_buflen;
    } else {
        *out_size = 0;
    }

    if (tmp_buf)
        free(tmp_buf);

    return assembly;
}

static void search_http2_data(proto_node *pn, gpointer data);

static void process_http2_header(proto_node *pn, http2_reassembly_t *res, const ushark_data_callbacks_t *cbs) {
    http2_hdr_info hinfo = {};
    proto_tree_children_foreach(pn, extract_http2_header, &hinfo);

    if (!hinfo.header_name || !hinfo.header_value)
        return;

    field_info *name_finfo = hinfo.header_name->finfo;
    field_info *val_finfo = hinfo.header_value->finfo;

    const guint8 *name_ptr = tvb_get_ptr(name_finfo->ds_tvb, name_finfo->start, name_finfo->length);
    const guint8 *val_ptr = tvb_get_ptr(val_finfo->ds_tvb, val_finfo->start, val_finfo->length);

    if (!name_ptr || !val_ptr || !*name_ptr)
        return;

    const char* name_ptr_c = (const char*) name_ptr;
    const char* val_ptr_c = (const char*) val_ptr;

    size_t tot_len = name_finfo->length + 2 + val_finfo->length + 2;
    char **buf_ptr;
    size_t *len_ptr;

    if (*name_ptr == ':') {
        // Extract HTTP/2 pseudo-headers
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
        buf_ptr = &res->headers_buf;
        len_ptr = &res->headers_buflen;
    }

    // Append header to buffer
    char *new_buf = realloc(*buf_ptr, *len_ptr + tot_len);
    if (!new_buf)
        // Memory allocation failed - skip this header
        return;

    *buf_ptr = new_buf;

    guint8 *p = (guint8*) *buf_ptr + *len_ptr;
    memcpy(p, name_ptr, name_finfo->length); p += name_finfo->length;
    *p++ = ':';
    *p++ = ' ';
    memcpy(p, val_ptr, val_finfo->length); p += val_finfo->length;
    *p++ = '\r';
    *p++ = '\n';
    *len_ptr += tot_len;
}

static void process_http2_stream(proto_node *pn, http2_tree_search_t *ts) {
    http2_stream_info_t stream_info = {0};
    proto_tree_children_foreach(pn, extract_http2_stream_info, &stream_info);

    if (stream_info.stream_id == 0)
        // Ignore control stream
        return;

    // Handle RST_STREAM frames (type 3)
    if (stream_info.frame_type == 3) {
        if (ts->cbs->on_http2_reset)
            ts->cbs->on_http2_reset(ts->conv->conv_index, stream_info.stream_id);

        http2_reassembly_key_t lookup_key = {
            .conv_index = ts->conv->conv_index,
            .stream_id = stream_info.stream_id
        };
        g_hash_table_remove(ts->ctx->reassembly_hash, &lookup_key);
        return;
    }

    http2_reassembly_key_t lookup_key = {
        .conv_index = ts->conv->conv_index,
        .stream_id = stream_info.stream_id
    };
    http2_reassembly_t *stream_res = (http2_reassembly_t*)
        g_hash_table_lookup(ts->ctx->reassembly_hash, &lookup_key);

    if (!stream_res) {
        stream_res = calloc(1, sizeof(http2_reassembly_t));

        http2_reassembly_key_t *stored_key = g_new(http2_reassembly_key_t, 1);
        *stored_key = lookup_key;
        g_hash_table_insert(ts->ctx->reassembly_hash, stored_key, stream_res);
    }

    // Process this stream
    http2_tree_search_t stream_ts = *ts;
    stream_ts.results = stream_res;
    stream_ts.cur_lvl++;
    proto_tree_children_foreach(pn, search_http2_data, &stream_ts);

    // Check if stream is complete and output
    if (stream_res->end_stream) {
        // Transfer ownership from data_buf to body_buf if needed
        if (!stream_res->body_buf && stream_res->data_buf) {
            stream_res->body_buf = stream_res->data_buf;
            stream_res->body_buflen = stream_res->data_buflen;
            stream_res->data_buf = NULL;
            stream_res->data_buflen = 0;
        }

        bool is_request = (stream_res->http2_hdrs.method != NULL);
        bool is_reply = (stream_res->http2_hdrs.status != NULL);

        void (*cb)(uint32_t, uint32_t, const unsigned char *, size_t) =
            (is_request ? ts->cbs->on_http2_request :
            (is_reply ? ts->cbs->on_http2_response : NULL));

        if (cb) {
            size_t size = 0;

            unsigned char *assembly = reassemble_http2_message(stream_res, &size);
            if (assembly) {
                cb(ts->conv->conv_index, stream_info.stream_id, assembly, size);
                free(assembly);
            }
        }

        http2_reassembly_key_t removal_key = {
            .conv_index = ts->conv->conv_index,
            .stream_id = stream_info.stream_id
        };
        g_hash_table_remove(ts->ctx->reassembly_hash, &removal_key);
    }
}

static void process_http2_body_data(proto_node *pn, http2_reassembly_t *res, const char *node_key) {
    if (strcmp(node_key, "http2.body.fragments") == 0) {
        if (!res->body_buf) {
            proto_node *reassembled_body = NULL;
            proto_tree_children_foreach(pn, extract_http2_reassembled_body, &reassembled_body);

            if (reassembled_body) {
                field_info *finfo = reassembled_body->finfo;
                const guint8 *body_ptr = tvb_get_ptr(finfo->ds_tvb, finfo->start, finfo->length);
                if (body_ptr && finfo->length > 0) {
                    // Allocate and copy the reassembled body data
                    res->body_buf = g_malloc(finfo->length);
                    memcpy(res->body_buf, body_ptr, finfo->length);
                    res->body_buflen = finfo->length;
                }
            }
        }
    } else if (strcmp(node_key, "http2.data.data") == 0) {
        if (!res->data_buf) {
            field_info *finfo = pn->finfo;
            const guint8 *body_ptr = tvb_get_ptr(finfo->ds_tvb, finfo->start, finfo->length);
            if (body_ptr && finfo->length > 0) {
                // Allocate and copy the data frame content
                res->data_buf = g_malloc(finfo->length);
                memcpy(res->data_buf, body_ptr, finfo->length);
                res->data_buflen = finfo->length;
            }
        }
    } else if (strcmp(node_key, "http2.flags") == 0) {
        uint8_t flags = fvalue_get_uinteger(&pn->finfo->value);
        if (flags & 0x01) // HTTP2_FLAGS_END_STREAM
            res->end_stream = 1;
    }
}

static void
search_http2_data(proto_node *pn, gpointer data)
{
    http2_tree_search_t* ts = (http2_tree_search_t*) data;

    if (ts->cur_lvl > HTTP2_LVL_HEADERS_BODY)
        return;

    const char *node_key = pn->finfo->hfinfo->abbrev;

    if (ts->cur_lvl == HTTP2_LVL_ROOT) {
        if (strcmp(node_key, "http2") == 0) {
            ts->cur_lvl++;
            proto_tree_children_foreach(pn, search_http2_data, ts);
            ts->cur_lvl--;
        }
    } else if (ts->cur_lvl == HTTP2_LVL_STREAM) {
        if (strcmp(node_key, "http2.stream") == 0) {
            process_http2_stream(pn, ts);
        }
    } else { // HTTP2_LVL_HEADERS_BODY
        // this is per-stream data set by process_http2_stream
        http2_reassembly_t *res = ts->results;
        if (!res)
            return;

        if (strcmp(node_key, "http2.header") == 0) {
            process_http2_header(pn, res, ts->cbs);
        } else {
            process_http2_body_data(pn, res, node_key);
        }
    }
}

ushark_http2_ctx_t* ushark_http2_init() {
  ushark_http2_ctx_t *ctx = (ushark_http2_ctx_t*) calloc(1, sizeof(ushark_http2_ctx_t));

  ctx->reassembly_hash = g_hash_table_new_full(
      http2_reassembly_key_hash,
      http2_reassembly_key_equal,
      g_free,
      (GDestroyNotify)free_http2_reassembly);

  return ctx;
}

void ushark_http2_cleanup(ushark_http2_ctx_t* ctx) {
  g_hash_table_destroy(ctx->reassembly_hash);
  free(ctx);
}

void ushark_http2_process_data(ushark_http2_ctx_t *ctx, epan_dissect_t *edt, conversation_t *conv, const ushark_data_callbacks_t *cbs) {
  // Initialize tree search context
  http2_tree_search_t ts = {};
  ts.cbs = cbs;
  ts.ctx = ctx;
  ts.conv = conv;
  ts.results = NULL;  // Will be set per-stream during traversal

  proto_tree_children_foreach(edt->tree, search_http2_data, &ts);
}
