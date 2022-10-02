#include "libft.h"

#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#define SA struct sockaddr

#define ACK			1
#define GARBAGE		2

int run = 1;

struct			tcp_packet {
	struct iphdr		ip;
	struct tcphdr		tcp;
};

void	print_ip4_header(struct ip *header);
void	print_icmp_header(struct icmphdr *header);
void	print_tcp_header(struct tcphdr *header);
void	print_udp_header(struct udphdr *header);

unsigned short tcp_checksum(struct iphdr *ip, struct tcphdr *tcp);
unsigned short checksum(const char *buf, unsigned int size);

static void intHandler(int code)
{
	(void)code;
	run = 0;
}

static int server_response(int sockfd, uint8_t type, void *received)
{
	(void)type;
	/* Data len */
	unsigned int len = 0;

	/* For tcp */
	char packet[sizeof(struct iphdr)+sizeof(struct tcphdr)+len];

	struct iphdr *rip = (struct iphdr *)received;
	struct tcphdr *rtcp = (struct tcphdr *)(received+sizeof(struct iphdr));

	struct iphdr *ip = (struct iphdr *)packet;
	struct tcphdr *tcp = (struct tcphdr *)(packet+sizeof(struct iphdr));

	ft_memset(packet, 0, sizeof(packet));

	/* Filling IP header */
	/* Version */
	ip->version = 4;
	/* Internet Header Length (how many 32-bit words are present in the header) */
	ip->ihl = sizeof(struct iphdr) / sizeof(uint32_t);
	/* Type of service */
	ip->tos = 0;
	/* Total length */
	ip->tot_len = htons(sizeof(packet));
	/* Identification (notes/ip.txt) */
	ip->id = 0;
	/* TODO: Set don't fragment flag ! */
	/* IP Flags + Fragment offset */
	ip->frag_off = 0;
	/* TTL */
	ip->ttl = 64;
	/* Protocol (TCP) */
	ip->protocol = IPPROTO_TCP;
	/* Checksum */
	ip->check = 0; /* Calculated after TCP header */
	/* Source ip */
	/* memcpy(&ip->saddr, &saddr->sin_addr.s_addr, sizeof(ip->saddr)); */
	/* Dest ip */
	memcpy(&ip->daddr, &rip->saddr, sizeof(ip->daddr));

	/* Filling TCP header */
	/* Source port */
	memcpy(&tcp->source, &rtcp->dest, sizeof(tcp->source));
	/* Destination port */
	memcpy(&tcp->dest, &rtcp->source, sizeof(tcp->dest));
	/* Seq num */
	tcp->seq = htons(0);
	/* Ack num */
	tcp->ack_seq = htons(0);
	/* Sizeof header / 4 */
	/* TODO: Options handling */
	tcp->doff = sizeof(struct tcphdr) /  4;
	/* Flags */
	tcp->fin = 0;
	tcp->syn = 1;
	tcp->rst = 0;
	tcp->psh = 0;
	tcp->ack = 1;
	tcp->urg = 0;
	/* WTF is this */
	tcp->window = htons(64240);
	/* Checksum */
	tcp->check = 0; /* Calculated after headers */
	/* Indicates the urgent data, only if URG flag set */
	tcp->urg_ptr = 0;

	/* Checksums */
	tcp->check = tcp_checksum(ip, tcp);
	ip->check = checksum((const char*)packet, sizeof(packet));

	print_ip4_header((struct ip *)packet);

	/* Sending handcrafted packet */
	if (send(sockfd, packet, sizeof(packet), 0) > 0)
		return 1;

	return 0;
}

static void server(uint16_t port)
{
	int len = 1024;
	char buffer[len];
	int sockfd;
	struct sockaddr_in servaddr;
	struct tcp_packet *packet;

	signal(SIGINT, intHandler);

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd == -1) {
		printf("[!] Socket creation failed...\n");
		exit(0);
	}

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
		printf("[!] Socket bind failed...\n");
		exit(0);
	}

	printf("[*] Server listening on port %d..\n", port);
	while (run) {
		bzero(buffer, len);
		recv(sockfd, buffer, len, 0);
		packet = (struct tcp_packet *)&buffer;
		if (packet->tcp.dest == htons(port)) {
			print_ip4_header((struct ip*)packet);
			server_response(sockfd, ACK, (void*)packet);
		}
	}

	printf("\n[*] Stopping server...\n");
	close(sockfd);
}

int main(int argc, char **argv)
{
	if (argc > 1)
		server(atoi(argv[1]));
}
