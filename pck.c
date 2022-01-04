#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<time.h>
#include <arpa/inet.h>

#define STRSIZE 1024

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;
typedef u_int16_t  u_short;
typedef u_int32_t u_int32;
typedef u_int16_t u_int16;
typedef u_int8_t u_int8;

struct time_val
{
    int tv_sec;
    int tv_usec;
};

struct pcap_pkthdr
{
    struct time_val ts;  /* time stamp */
    bpf_u_int32 caplen; /* length of portion present */
    bpf_u_int32 len;    /* length this packet (off wire) */
};

typedef struct FramHeader_t
{
    u_int8 DstMAC[6];
    u_int8 SrcMAC[6];
    u_short FrameType;
} FramHeader_t;

typedef struct IPHeader_t
{
    u_int8 Ver_HLen;
    u_int8 TOS;
    u_int16 TotalLen;
    u_int16 ID;
    u_int16 Flag_Segment;
    u_int8 TTL;
    u_int8 Protocol;
    u_int16 Checksum;
    u_int32 SrcIP;
    u_int32 DstIP;
} IPHeader_t;


typedef struct TCPHeader_t
{
    u_int16 SrcPort;
    u_int16 DstPort;
    u_int32 SeqNO;
    u_int32 AckNO;
    u_int8 HeaderLen;
    u_int8 Flags;
    u_int16 Window;
    u_int16 Checksum;
    u_int16 UrgentPointer;
} TCPHeader_t;

typedef struct UDPHeader_t{
    u_int16 SrcPort;
    u_int16 DstPort;
    u_int16 HeaderLen;
    u_int16 Checksum;
} UDPHeader_t;

static const char *mac_ntoa(u_int8_t *d) {
    static char mac[STRSIZE][18];
    static int which = -1;
    which = (which + 1 == STRSIZE ? 0 : which + 1);
    memset(mac[which], 0, 18);
    snprintf(mac[which], sizeof(mac[which]), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
    return mac[which];
}

int main(int argc, char *argv[])
{
	struct pcap_pkthdr *pkt_header;
	FramHeader_t *mac_header;
	IPHeader_t *ip_header;
	TCPHeader_t *tcp_header;
	UDPHeader_t *udp_header;
	FILE *desc;
	if (argc < 2) {
		fprintf(stderr, "usage:./pck [filename]\n");
		exit(1);
	}

	if ((desc=fopen(argv[1], "r")) == NULL) {
		fprintf(stderr, "file error\n");
		exit(1);
	}
	//Initailize
	pkt_header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
	mac_header = (FramHeader_t *)malloc(sizeof(FramHeader_t));
	ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
	tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));
	udp_header = (UDPHeader_t *)malloc(sizeof(UDPHeader_t));

	int pkt_offset = 24;
	char my_time[STRSIZE];
	char src_ip[STRSIZE], dst_ip[STRSIZE];
	int src_port, dst_port;
	while (fseek(desc, pkt_offset, SEEK_SET) == 0) {
		//time
		memset(pkt_header, 0, sizeof(struct pcap_pkthdr));

		if (fread(pkt_header, 16, 1, desc) != 1) {
			printf("\nread end of pcap file\n");
			break;
		}

		pkt_offset += 16 + pkt_header->caplen;
		printf("size: %d\n", pkt_header->caplen);

		struct tm *timeinfo;
        	time_t t = (time_t)(pkt_header->ts.tv_sec);
        	timeinfo = localtime(&t);
		strftime(my_time, sizeof(my_time), "%Y-%m-%d %H:%M:%S", timeinfo);
		printf("%s\n", my_time);
		//MAC
		memset(mac_header, 0, sizeof(FramHeader_t));
		if (fread(mac_header, sizeof(FramHeader_t), 1, desc) != 1) {
            		printf("Can not read Fram_header\n");
            		break;
        	}
		printf("SrcMAC:%s DstMAC:%s\n", mac_ntoa(mac_header->SrcMAC), mac_ntoa(mac_header->DstMAC));
		printf("EtherType:%04x\n",ntohs(mac_header->FrameType));
		//IP
		memset(ip_header, 0, sizeof(IPHeader_t));
		if (fread(ip_header, sizeof(IPHeader_t), 1, desc) != 1) {
			printf("Can not read IP header\n");
			break;
		}
		inet_ntop(AF_INET, (void *)&(ip_header->SrcIP), src_ip, 16);
		inet_ntop(AF_INET, (void *)&(ip_header->DstIP), dst_ip, 16);
		printf("SrcIP:%s DstIP:%s\n", src_ip, dst_ip);

		if ((ip_header->Protocol!=6) && (ip_header->Protocol!=17)) {
			printf("Not TCP or UDP\n");
			continue;
		}
		//TCP
		if (ip_header->Protocol == 6) {
			memset(tcp_header, 0, sizeof(TCPHeader_t));
			if (fread(tcp_header, sizeof(TCPHeader_t), 1, desc) != 1) {
				printf("Can not read TCP hader\n");
				break;
			}
			src_port = ntohs(tcp_header->SrcPort);
			dst_port = ntohs(tcp_header->DstPort);
			printf("SrcPort:%d DstPort:%d\n", src_port, dst_port);
		}
		//UDP
		else if (ip_header->Protocol == 17) {
			memset(udp_header, 0, sizeof(UDPHeader_t));
			if (fread(tcp_header, sizeof(UDPHeader_t), 1, desc) != 1) {
                                printf("Can not read UDP hader\n");
                                break;
                        }
			src_port = ntohs(udp_header->SrcPort);
                        dst_port = ntohs(udp_header->DstPort);
		}
		printf("----------------------------\n");
	}
	fclose(desc);
	free(pkt_header);
	free(mac_header);
	free(ip_header);
	free(tcp_header);
	free(udp_header);
}
