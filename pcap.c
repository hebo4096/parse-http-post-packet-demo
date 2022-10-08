#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap/pcap.h>

#define MAX_DUMP_SIZE  200

void usage()
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "pcap <if name>\n");
	exit(-1);
}

void dump_buffer(const u_char *buff, size_t n, size_t limit)
{
	int i;
	int binary_counter = 0;
	int binary_prev = 0xffff;
	
	for (i = 0 ; i < n ; i++) {
		if (buff[i] == 0x4f && binary_prev == 0x50) {
			binary_counter++;
		}

		if (buff[i] == 0x53 && binary_prev == 0x4f) {
			binary_counter++;
		}

		if (buff[i] == 0x54 && binary_prev == 0x53) {
			binary_counter++;
			break;
		}
		
		// cache previous binary
		binary_prev = buff[i];
	}

	// show binary when packet is http post request.
	if (binary_counter == 3) {
		puts("\n----- HTTP POST packet received! -----\n");
		for (i = 0 ; i < n ; i++) {
			if (i == limit) {
				break;
			}
			if (i % 16 == 0) {
				printf("%08x  ", i);
			}
			printf("%02x ", buff[i]);
			if (i % 16 == 15) {
				printf("\n");
			}
		}
	}
}

// callback for pcap_loop.
void proc_packet(u_char *user, struct pcap_pkthdr *info, const u_char *buff)
{
	struct tm t;

	localtime_r(&(info->ts.tv_sec), &t);

	// printf("%4d-%02d-%02d %02d:%02d:%02d.%ld Received a Packet\n",
	//       t.tm_year + 1900,
	//       t.tm_mon  + 1,
	//       t.tm_mday,
	//       t.tm_hour,
	//       t.tm_min,
	//       t.tm_sec,
	//       info->ts.tv_usec);
	// printf("Captured Length: %d, Packet Length: %d\n", info->caplen, info->len);

	dump_buffer(buff, info->caplen, MAX_DUMP_SIZE);
}

int main(int argc, char *argv[])
{
	char *if_name;
	pcap_t *capt = NULL;
	char err_str[PCAP_ERRBUF_SIZE];

	if (argc < 2) {
		usage();
	}

	if_name = argv[1];

	if((capt = pcap_open_live(if_name, 65536, 1, 250, err_str)) == NULL) {
		fprintf(stderr, "%s", err_str);
		return(-1);
	}

	printf("-- Start capture --\n");

	while(1) {
		if(pcap_loop(capt, -1, (pcap_handler) proc_packet, (u_char *) NULL) == -1) {
			fprintf(stderr, "err");
			return -1;
		}
	}

	return 0;
}
