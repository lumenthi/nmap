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
#include <sys/types.h>
#include <sys/wait.h>

#define SA struct sockaddr

#define ENABLE 1
#define DISABLE 2

#define OPEN 1
#define FILTERED 2
#define CLOSED 3

int run = 1;

struct			tcp_packet {
	struct iphdr		ip;
	struct tcphdr		tcp;
};

int dconfig(char *destination, uint16_t port, struct sockaddr_in *daddr,
	char **hostname);
int sconfig(char *destination, struct sockaddr_in *saddr);

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

static void update_cursor(int sockfd, unsigned int len, int sport,
	struct iphdr *ip, uint16_t bindport)
{
	if (ip->saddr != ip->daddr)
		return;

	char buffer[len];
	struct tcp_packet *packet;
	int pport = -1;

	while (pport != sport) {
		if (recv(sockfd, buffer, len, MSG_DONTWAIT) < 0)
			return;
		packet = (struct tcp_packet *)buffer;
		/* printf("bindport: %d, dest: %d\n", bindport, ntohs(packet->tcp.dest)); */
		if (packet->tcp.dest == htons(bindport)) {
			pport = packet->tcp.dest;
			/* printf("pport: %d, sport: %d\n", ntohs(pport), ntohs(sport)); */
		}
	}
}

static int server_response(int sockfd, uint8_t type, void *received,
	uint16_t bindport)
{
	(void)type;
	/* Data len */
	unsigned int len = 0;

	/* Dest string */
	char *destination;

	/* Structs addr */
	struct sockaddr_in saddr;
	struct sockaddr_in daddr;

	/* For tcp */
	char packet[sizeof(struct iphdr)+sizeof(struct tcphdr)+len];

	struct iphdr *rip = (struct iphdr *)received;
	struct tcphdr *rtcp = (struct tcphdr *)(received+sizeof(struct iphdr));

	struct iphdr *ip = (struct iphdr *)packet;
	struct tcphdr *tcp = (struct tcphdr *)(packet+sizeof(struct iphdr));

	/* Filling sockaddr structs */
	destination = inet_ntoa(*(struct in_addr *)&rip->saddr);
	dconfig(destination, tcp->source, &daddr, NULL);
	sconfig(destination, &saddr);
	saddr.sin_port = rtcp->dest;

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
	/* Source ip */
	memcpy(&ip->saddr, &rip->saddr, sizeof(ip->saddr));
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

	/* print_ip4_header((struct ip *)packet); */

	/* Sending handcrafted packet */
	if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&daddr,
		sizeof(struct sockaddr)) > 0)
	{
		update_cursor(sockfd, sizeof(packet), tcp->source, ip, bindport);
		printf("[*] Sent packet:\n");
		print_ip4_header((struct ip *)packet);
		return 1;
	}
	else {
		printf("[!] Failed to send packet\n");
		exit(1);
	}

	return 0;
}

static void print_usage(char *path)
{
	printf("Usage: %s {PORT} {MODE}\n"
	"Modes:\n"
	"1: OPEN\n2: FILTERED\n3: CLOSED\n", path);
}

static void iptable(char *sport, uint8_t filter, uint8_t mode)
{
	(void)filter;
	char *aiptables_enable[] = {"/sbin/iptables", "-A", "OUTPUT", "-p", "tcp",
		"--source-port", sport, "--tcp-flags", "RST", "RST", "-j",
		"DROP", NULL};
	char *aiptables_disable[] = {"/sbin/iptables", "-D", "OUTPUT", "-p", "tcp",
		"--source-port", sport, "--tcp-flags", "RST", "RST", "-j",
		"DROP", NULL};

	char *aiptables_cenable[] = {"/sbin/iptables", "-A", "INPUT", "-p", "tcp",
		"--dport", sport, "-j", "REJECT", "--reject-with", "tcp-reset",
		NULL};
	char *aiptables_cdisable[] = {"/sbin/iptables", "-D", "INPUT", "-p", "tcp",
		"--dport", sport, "-j", "REJECT", "--reject-with", "tcp-reset",
		NULL};

	char **selected_mode;

	int status;
	pid_t pid = fork();

	if (pid == -1)
		printf("[!] Failed to execute iptable commande\n");
	else if (pid > 0)
		waitpid(pid, &status, 0);
	else {
		if (mode == ENABLE) {
			selected_mode = aiptables_enable;
			if (filter == CLOSED)
				selected_mode = aiptables_cenable;
		}
		else if (mode == DISABLE) {
			selected_mode = aiptables_disable;
			if (filter == CLOSED)
				selected_mode = aiptables_cdisable;
		}

		if (execve("/sbin/iptables", selected_mode, NULL) == -1)
			printf("[!] Failed to modify IPTABLE rule, run as sudo\n");
		_exit(EXIT_FAILURE);   // exec never returns
	}
}

/* sport: string port */
static void server(char *path, char *sport, uint16_t port, uint8_t mode)
{
	int len = 1024;
	char buffer[len];
	int sockfd;
	int one = 1;
	struct sockaddr_in servaddr;
	struct tcp_packet *packet;

	if (mode != OPEN && mode != FILTERED && mode != CLOSED) {
		print_usage(path);
		return;
	}

	signal(SIGINT, intHandler);

	iptable(sport, mode, ENABLE);

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd == -1) {
		printf("[!] Socket creation failed...\n");
		return;
	}

	if ((setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		printf("[!] Socket option failed...\n");
		close(sockfd);
		return;
	}

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
		printf("[!] Socket bind failed...\n");
		close(sockfd);
		return;
	}

	printf("[*] Server listening on port %d..\n", port);
	while (run) {
		bzero(buffer, len);
		recv(sockfd, buffer, len, 0);
		packet = (struct tcp_packet *)&buffer;
		if (packet->tcp.dest == htons(port)) {
			printf("[*] Received packet:\n");
			print_ip4_header((struct ip*)packet);
			if (mode != FILTERED)
				server_response(sockfd, mode, (void*)packet, port);
		}
	}

	printf("\n[*] Stopping server...\n");
	iptable(sport, mode, DISABLE);
	close(sockfd);
}

int main(int argc, char **argv)
{
	if (argc > 2)
		server(argv[0], argv[1], atoi(argv[1]), atoi(argv[2]));
	else
		print_usage(argv[0]);
}
