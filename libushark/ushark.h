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
USHARK_EXPORT const char* ushark_dissect(ushark_t *sk, const unsigned char *buf, const struct pcap_pkthdr *hdr);

typedef void (*ushark_tls_data_callback)(const unsigned char *plain_data, unsigned int data_len);
USHARK_EXPORT void ushark_dissect_tls(ushark_t *sk, const unsigned char *buf, const struct pcap_pkthdr *hdr, ushark_tls_data_callback cb);

#endif
