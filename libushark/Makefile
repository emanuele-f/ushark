.PHONY: all clean

WIRESHARK := ../../wireshark
WLIBS := $(WIRESHARK)/build/run

CFLAGS := -g -O0 -I$(WIRESHARK) -I$(WIRESHARK)/include -I$(WIRESHARK)/build \
	`pkgconf --cflags gmodule-2.0 gnutls libgcrypt libnghttp2`

%.o :
	$(CC) $(CFLAGS) -Wall -c -o $@ $^

all: pcap_example

pcap_example: pcap_example.o libushark.a $(WLIBS)/libwireshark.a \
		$(WLIBS)/libwiretap.a $(WLIBS)/libversion_info.a $(WLIBS)/libwsutil.a \
		$(WLIBS)/libui.a
	$(CC) -o $@ $(CFLAGS) $^ \
		 `pkgconf --libs libpcre2-8 libpcap glib-2.0 libgcrypt libnghttp2 gnutls libcares libbrotlidec liblz4 libzstd zlib` -lm

pcap_example.o: pcap_example.c

libushark.a: frame_tvbuff.o ushark.o http2.o
	ar rcs $@ $^

frame_tvbuff.o: $(WIRESHARK)/frame_tvbuff.c

ushark.o: ushark.c
http2.o: http2.c

clean:
	rm -f *.o libushark.a pcap_example
