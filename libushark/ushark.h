#ifndef _USHARK_H_
#define _USHARK_H_

#define USHARK_EXPORT __attribute__((visibility("default")))

typedef struct ushark ushark_t;
typedef struct epan_dfilter dfilter_t;
struct pcap_pkthdr;

USHARK_EXPORT void ushark_init();
USHARK_EXPORT void ushark_cleanup();

USHARK_EXPORT ushark_t* ushark_new(int pcap_encap, const char *dfilter);
USHARK_EXPORT void ushark_destroy(ushark_t *sk);
USHARK_EXPORT void ushark_set_pref(const char *name, const char *val);

typedef struct {
  void (*on_http1_data)(uint32_t conversation_id, const unsigned char *plain_data, size_t data_len);
  void (*on_http2_request)(uint32_t conversation_id, uint32_t stream_id, const unsigned char *plain_data, size_t data_len);
  void (*on_http2_response)(uint32_t conversation_id, uint32_t stream_id, const unsigned char *plain_data, size_t data_len);
  void (*on_http2_reset)(uint32_t conversation_id, uint32_t stream_id);
} ushark_data_callbacks_t;
USHARK_EXPORT void ushark_set_callbacks(ushark_t *sk, const ushark_data_callbacks_t *cbs);

/** @brief Dissect the HTTP data in the given buffer, possibly decrypting it via the keylog
  * @return The dissected JSON if no callbacks are set, NULL otherwise
  * @note the callbacks can be set via ushark_set_callbacks, which changes the operating mode
  */
USHARK_EXPORT const char* ushark_dissect(ushark_t *sk, const unsigned char *buf, const struct pcap_pkthdr *hdr);

#endif
