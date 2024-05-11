#ifndef _USHARK_H_
#define _USHARK_H_

typedef struct ushark ushark_t;
typedef struct epan_dfilter dfilter_t;
struct pcap_pkthdr;

void ushark_init();
void ushark_cleanup();

ushark_t* ushark_new(int pcap_encap, const char *dfilter);
void ushark_destroy(ushark_t *sk);
void ushark_set_pref(const char *name, const char *val);
const char* ushark_dissect(ushark_t *sk, const unsigned char *buf, const struct pcap_pkthdr *hdr);

typedef void (*ushark_tls_data_callback)(const unsigned char *plain_data, unsigned int data_len);
void ushark_dissect_tls(ushark_t *sk, const unsigned char *buf, const struct pcap_pkthdr *hdr, ushark_tls_data_callback cb);

#endif
