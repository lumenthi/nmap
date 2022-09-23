#include "nmap.h"

static unsigned short csum(unsigned short *buf, int len)
{
	unsigned long sum;

	for(sum=0; len>0; len--)
		sum += *buf++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

static void send_syn(int sockfd,
	struct sockaddr_in *saddr, struct sockaddr_in *daddr)
{
	unsigned int len = 0;

	char packet[sizeof(struct iphdr)+sizeof(struct tcphdr)+len];
	struct iphdr *ip = (struct iphdr *)packet;
	struct tcphdr *tcp = (struct tcphdr *)(packet+sizeof(struct iphdr));

	ft_memset(packet, 0, sizeof(packet));

	/* Version */
	ip->version = 4;
	/* Internet Header Length (how many 32-bit words are present in the header) */
	ip->ihl = sizeof(struct iphdr) / sizeof(uint32_t);
	/* Type of service */
	ip->tos = 0;
	/* Total length */
	ip->tot_len = sizeof(packet);
	/* TODO: Identification (check notes.txt) */
	ip->id = htonl(rand() % 65535);
	/* TODO: Set don't fragment flag ! IP Flags + Fragment offset */
	ip->frag_off = 0;
	/* TTL */
	ip->ttl = 64;
	/* Protocol (TCP) */
	ip->protocol = IPPROTO_TCP;
	/* Checksum */
	ip->check = 0; /* TODO: Calculate it after the TCP header */
	/* Source ip */
	ip->saddr = saddr->sin_addr.s_addr;
	/* Dest ip */
	ip->daddr = daddr->sin_addr.s_addr;

	/* Source port */
	tcp->source = saddr->sin_port;
	/* Destination port */
	tcp->dest = daddr->sin_port;
	/* Seq num */
	tcp->seq = htonl(1);
	/* Ack num */
	tcp->ack_seq = htonl(0);
	/* Sizeof header */
	tcp->doff = 10;
	/* FLAGS */
	tcp->fin = 0;
	tcp->syn = 1;
	tcp->rst = 0;
	tcp->psh = 0;
	tcp->ack = 0;
	tcp->urg = 0;
	/* WTF is this */
	tcp->window = htons(64240);
	/* Checksum */
	tcp->check = 0;
	/* Indicates the urgent data, only if URG flag set */
	tcp->urg_ptr = 0;

	/* Checksums */
	ip->check = csum((unsigned short *)packet, sizeof(packet));

	printf("TCP: %ld\n", sizeof(struct tcphdr));
	printf("len: %d\n", ip->tot_len);
	printf("proto: %d\n", ip->protocol);

	sendto(sockfd, packet, ip->tot_len, 0, (struct sockaddr *)daddr, sizeof(struct sockaddr));
	write(sockfd, packet, sizeof(packet));
}

int sconfig(int sockfd, struct sockaddr_in *saddr)
{
	socklen_t addlen = sizeof(struct sockaddr);

	ft_memset(saddr, 0, sizeof(*saddr));

	saddr->sin_family = AF_INET;
	saddr->sin_port = htons(rand() % 65535);
	if (inet_pton(AF_INET, "127.0.0.1", &(saddr->sin_addr)) != 1)
		return 1;

	/* TODO: Remove, debug */
	printf("[*] Selected port number: %d\n", ntohs(saddr->sin_port));
	return 0;

	if ((bind(sockfd, (struct sockaddr *)saddr, sizeof(struct sockaddr)) != 0))
		return 1;

	/* TODO: getsockname not allowed */
	getsockname(sockfd, (struct sockaddr *)saddr, &addlen);

	printf("[*] Selected port number: %d\n", ntohs(saddr->sin_port));

	return 0;
}

int dconfig(char *destination, uint16_t port, struct sockaddr_in *daddr)
{
	struct hostent *host;

	/* TODO: check memset returns */
	ft_memset(daddr, 0, sizeof(*daddr));
	if (!(host = gethostbyname(destination)))
		return 1;

	daddr->sin_family = host->h_addrtype;
	daddr->sin_port = htons(port);
	/* TODO: check return */
	ft_memcpy(&(daddr->sin_addr.s_addr), host->h_addr_list[0], host->h_length);

	printf("[*] Destination: %s (%s)\n", destination, inet_ntoa(daddr->sin_addr));

	return 0;
}

int syn_scan(char *destination, uint16_t port)
{
	int sockfd;
	int one = 1;
	struct sockaddr_in saddr;
	struct sockaddr_in daddr;

	if (dconfig(destination, port, &daddr) != 0) {
		fprintf(stderr, "%s: Name or service not known\n", destination);
		return 1;
	}

	/* Socket creation */
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		fprintf(stderr, "%s: Failed to create TCP socket\n", destination);
		return 1;
	}

	/* Set options */
	if ((setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		fprintf(stderr, "%s: Failed to set TTL option\n", destination);
		close(sockfd);
		return 1;
	}

	if (sconfig(sockfd, &saddr)) {
		fprintf(stderr, "%s: Source configuration failed\n", destination);
		close(sockfd);
		return 1;
	}

	if ((connect(sockfd, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) != 0)) {
		fprintf(stderr, "%s: Failed to connect to host\n", destination);
		close(sockfd);
		return 1;
	}

	send_syn(sockfd, &saddr, &daddr);

	close(sockfd);
	return 0;
}

int ft_nmap(char *destination, uint8_t args, char *path)
{
	(void)args;

	if (!destination) {
		fprintf(stderr, "%s: Empty hostname\n", path);
		return 1;
	}

	if (getuid() != 0) {
		fprintf(stderr, "%s: %s: Not allowed to create raw sockets, run as root\n",
			path, destination);
		return 1;
	}

	syn_scan(destination, 22);

	return 0;
}
