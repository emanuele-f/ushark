#ifndef _USHARK_HTTP2_H_
#define _USHARK_HTTP2_H_

#include <epan/epan_dissect.h>
#include <epan/epan.h>
#include <epan/conversation.h>

#include "ushark.h"

typedef struct ushark_http2_ctx ushark_http2_ctx_t;

ushark_http2_ctx_t* ushark_http2_init();
void ushark_http2_cleanup(ushark_http2_ctx_t *ctx);
void ushark_http2_process_data(ushark_http2_ctx_t *ctx, epan_dissect_t *edt, conversation_t *conv, ushark_tls_data_callback tls_cb);

#endif
