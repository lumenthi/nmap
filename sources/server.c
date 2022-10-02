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

#define SA struct sockaddr

struct			tcp_packet {
	struct iphdr		ip;
	struct tcphdr		tcp;
};

void	print_ip4_header(struct ip *header);
void	print_icmp_header(struct icmphdr *header);
void	print_tcp_header(struct tcphdr *header);
void	print_udp_header(struct udphdr *header);

void server(uint16_t port)
{
	int len = 1024;
	char buffer[len];
	int sockfd;
	struct sockaddr_in servaddr;
	struct tcp_packet *packet;

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd == -1) {
		printf("socket creation failed...\n");
		exit(0);
	}

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
		printf("socket bind failed...\n");
		exit(0);
	}

	printf("[*] Server listening on port %d..\n", port);
	while (1) {
		bzero(&servaddr, sizeof(servaddr));
		recv(sockfd, buffer, len, 0);
		packet = (struct tcp_packet *)&buffer;
		if (packet->tcp.dest == htons(port))
			print_ip4_header((struct ip*)packet);
	}
	close(sockfd);
}

int main(int argc, char **argv)
{
	if (argc > 1)
		server(atoi(argv[1]));
}
