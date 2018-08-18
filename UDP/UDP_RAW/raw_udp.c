#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

#define BUFFLEN 512

struct _udp_header {
	unsigned short src_port;
	unsigned short dest_port;
	unsigned short len;
	unsigned short chk_summ;
};

struct _ip_header {
	unsigned char vhl;
	unsigned char tos;
	unsigned short len;
	unsigned short id;
	unsigned short offset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	
	struct in_addr src, dst;
};

struct _mac_addr {
	unsigned char addr[6];
};

struct _eth_header {
	struct _mac_addr mac_dest;
	struct _mac_addr mac_src;
	unsigned short type;
};

unsigned int _crc16_ip(char *buf) {
	unsigned int sum = 0;
	unsigned short *word = (unsigned short *) buf;
	for (int i = 0; i < 10; ++i, ++word) {
		sum += *word;
	}
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum += (sum >> 16);
	sum = ~sum;
	return sum;
}

void _udp_wrapper (char *buf, int offset, char *port, int msg_len) {
	struct _udp_header *uh;
	uh = (struct _udp_header *) (buf + offset);
	uh->src_port = htons(7777);
	uh->dest_port = htons(7777);
	uh->len = htons(msg_len + 8);
	uh->chk_summ = 0;
}

void _ip_wrapper (char *buf, int offset, char *address, int all_len) {
	struct _ip_header *ih;
	ih = (struct _ip_header *) (buf + offset);
	ih->vhl = (4 << 4) | 5;
	ih->tos = 0;
	ih->len = htons(20 + 14);
	ih->id = htons(12345);
	printf("ip id: %d\n", ih->id);
	ih->ttl = 64;
	ih->offset = 0;
	ih->protocol = 17;
	ih->checksum = 0;
	ih->src.s_addr = inet_addr("192.168.126.129");
	ih->dst.s_addr = inet_addr("192.168.1.11");
	ih->checksum = _crc16_ip(ih);
}

void _eth_wrapper (char *buf, struct _mac_addr dest, struct _mac_addr src) {
	struct _eth_header *eh;
	eh = (struct _eth_header *) buf;
	eh->mac_dest = dest;
	eh->mac_src = src;
	eh->type = htons(0x0800);
}

void _headers_print (char *buf) {
	unsigned short *u_src = &buf[34];
	unsigned short *u_dest = &buf[36];
	unsigned short *u_len = &buf[38];
	unsigned short *u_chk = &buf[40];
	printf("udp header: %d %d %d %d\n", *u_src, *u_dest, ntohs(*u_len), *u_chk);
}


int main (int argc, char **argv) 
{
	int raw_socket, length_addr;
	
	struct sockaddr_ll addr = {0};

	struct _mac_addr dest = {{0x00, 0x50, 0x56, 0xe1, 0xf0, 0xae}};
	struct _mac_addr src = {{0x00, 0x0c, 0x29, 0x67, 0xc5, 0x16}};

	if ((raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket error");
		exit(1);
	}

	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = if_nametoindex("ens33");
	addr.sll_halen = 6;
	memcpy(addr.sll_addr, &dest, 6);
	
	printf("%s\n", "Net init done!");

	char *buf = malloc(BUFFLEN);
	bzero(buf, BUFFLEN);

	_udp_wrapper(buf, 34, argv[2], sizeof("hello"));
	_ip_wrapper(buf, 14, argv[1], sizeof("hello") + 8);
	_eth_wrapper(buf, dest, src);
	_headers_print(buf);

	strncat(buf + 42, "hello", 5);

	printf("%s", "send packet...");
	if (sendto(raw_socket, buf, sizeof("hello") + 14 + 20 + 8,
	 NULL, (struct sockaddr_ll *) &addr, sizeof(addr)) <= 0) {
		perror("send error");
		exit(1);
	}
	printf("%s\n", "send done");
	
	free(buf);
	close(raw_socket);
}
