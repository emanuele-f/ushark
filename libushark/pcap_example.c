#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include "ushark.h"

static bool short_mode = false;

static void bytes_to_hex(const unsigned char *data, size_t len, char *hex_out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_out + (i * 2), "%02x", data[i]);
    }
    hex_out[len * 2] = '\0';
}

static void print_data(const unsigned char *plain_data, size_t data_len) {
    char body_buf[64] = {0};
    const unsigned char* payload = plain_data;
    size_t payload_size = data_len;

    if(!plain_data)
        return;

    printf("-----------------------\n");

    if (short_mode) {
        // Find the end of headers
        const unsigned char *headers_end = (const unsigned char *) memmem(plain_data, data_len, "\r\n\r\n", 4);
        if (headers_end) {
            headers_end += 4;
            payload_size = headers_end - plain_data;

            if ((headers_end - plain_data) < data_len) {
                char* body_out = body_buf;
                const unsigned char *body_start = headers_end;
                unsigned int body_len = data_len - (body_start - plain_data);

                if (body_len <= 16) {
                    // message is 16 bytes or less - show entire message
                    bytes_to_hex(body_start, body_len, body_out);
                    body_out += body_len;
                } else {
                    // show first and last 8 bytes (16 hex)
                    bytes_to_hex(body_start, 8, body_out);
                    body_out += 16;
                    *body_out++ = '.';
                    *body_out++ = '.';
                    bytes_to_hex(body_start + (body_len - 8), 8, body_out);
                    body_out += 16;
                }

                *body_out++ = '\r';
                *body_out++ = '\n';
            }
        }
    }

    unsigned char *buf = malloc(payload_size);
    if (buf) {
        memcpy(buf, payload, payload_size);

        // replace non-printable chars with @
        for (unsigned int i = 0; i < payload_size; i++) {
            if (!isprint(buf[i]) && !isspace(buf[i]))
                buf[i] = '.';
        }

        printf("%.*s%s\n", (int) payload_size, buf,
          body_buf[0] ? body_buf : "");

        free(buf);
    }
}

static void handle_http1_data(uint32_t conversation_id, const unsigned char *plain_data, size_t data_len) {
    printf("[HTTP1 conv:%u]\n", conversation_id);
    print_data(plain_data, data_len);
}

static void handle_http2_request(uint32_t conversation_id, uint32_t stream_id, const unsigned char *plain_data, size_t data_len) {
    printf("[HTTP2.REQ conv:%u stream:%u]\n", conversation_id, stream_id);
    print_data(plain_data, data_len);
}

static void handle_http2_response(uint32_t conversation_id, uint32_t stream_id, const unsigned char *plain_data, size_t data_len) {
    printf("[HTTP2.RES conv:%u stream:%u]\n", conversation_id, stream_id);
    print_data(plain_data, data_len);
}

static void handle_http2_reset(uint32_t conversation_id, uint32_t stream_id) {
    printf("[HTTP2.RST conv:%u steam:%u]\n", conversation_id, stream_id);
    printf("-----------------------\n");
}

static void handle_pkt(u_char *user, const struct pcap_pkthdr *hdr, const u_char *buf) {
    ushark_t *sk = (ushark_t*) user;

    const char *json = ushark_dissect(sk, buf, hdr);
    if(json)
        puts(json);
}

static void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s -f <pcap_file> [-d <display_filter>] [-k <keylog_file>] [-2] [-h]\n", progname);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -f, --file <path>           Path to pcap file (required)\n");
    fprintf(stderr, "  -d, --display-filter <expr> Display filter expression\n");
    fprintf(stderr, "  -k, --keylog <path>         Path to TLS keylog file\n");
    fprintf(stderr, "  -2, --http2 <path>          Decode and print HTTP2 data\n");
    fprintf(stderr, "  -s, --short                 Print max 16 Bytes of HTTP body\n");
    fprintf(stderr, "  -h, --help                  Show this help message\n");
}

int main(int argc, char **argv) {
    static char errbuf[PCAP_ERRBUF_SIZE];
    char *pcap_path = NULL;
    char *dfilter = NULL;
    char *keylog_path = NULL;
    bool http2_mode = false;
    int opt;

    static struct option long_options[] = {
        {"file",           required_argument, 0, 'f'},
        {"display-filter", required_argument, 0, 'd'},
        {"keylog",         required_argument, 0, 'k'},
        {"http2",          no_argument,       0, '2'},
        {"short",          no_argument,       0, 's'},
        {"help",           no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "f:d:k:2sh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'f':
                pcap_path = optarg;
                break;
            case 'd':
                dfilter = optarg;
                break;
            case 'k':
                keylog_path = optarg;
                break;
            case '2':
                http2_mode = true;
                break;
            case 's':
                short_mode = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }

    if (!pcap_path) {
        fprintf(stderr, "Error: pcap file is required\n\n");
        print_usage(argv[0]);
        return -1;
    }

    pcap_t *pd = pcap_open_offline(pcap_path, errbuf);
    if(!pd) {
        fprintf(stderr, "pcap open failed: %s\n", errbuf);
        return -1;
    }

    ushark_init();

    if(keylog_path)
        ushark_set_pref("tls.keylog_file", keylog_path);

    ushark_t *sk = ushark_new(pcap_datalink(pd), dfilter);
    
    if (http2_mode) {
        ushark_data_callbacks_t cbs = {
          .on_http1_data = handle_http1_data,
          .on_http2_request = handle_http2_request,
          .on_http2_response = handle_http2_response,
          .on_http2_reset = handle_http2_reset,
        };

        ushark_set_callbacks(sk, &cbs);
    }

    pcap_loop(pd, 0, handle_pkt, (u_char*)sk);

    ushark_destroy(sk);
    ushark_cleanup();
    pcap_close(pd);
}
