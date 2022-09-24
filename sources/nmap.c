#include "nmap.h"

static unsigned short checksum(const char *buf, unsigned int size)
{
	unsigned sum = 0, i;

	/* Accumulate checksum */
	for (i = 0; i < size - 1; i += 2)
	{
		unsigned short word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}

	/* Handle odd-sized case */
	if (size & 1)
	{
		unsigned short word16 = (unsigned char) buf[i];
		sum += word16;
	}

	/* Fold to get the ones-complement result */
	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

	/* Invert to get the negative in ones-complement arithmetic */
	return ~sum;
}

static unsigned short tcp_checksum(struct iphdr *ip, struct tcphdr *tcp)
{
	struct pseudo_header
	{
		u_int32_t source_address;
		u_int32_t dest_address;
		u_int8_t placeholder;
		u_int8_t protocol;
		u_int16_t tcp_length;
	} psh;

	char ppacket[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];

	psh.source_address = ip->saddr;
	psh.dest_address = ip->daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	/* TODO: Options calculation */
	psh.tcp_length = htons(sizeof(struct tcphdr));

	ft_memcpy(ppacket, (char*)&psh, sizeof(struct pseudo_header));
	ft_memcpy(ppacket+sizeof(struct pseudo_header),
		tcp, sizeof(struct tcphdr));

	return checksum(ppacket, sizeof(ppacket));
}

static void update_cursor(int sockfd, unsigned int len)
{
	char buffer[len];
	struct tcp_packet *packet;

	read(sockfd, buffer, len);
	packet = (struct tcp_packet *)buffer;
	printf("[*] Sent packet\n");
	print_ip4_header((struct ip *)&packet->ip);
	print_tcp_header(&packet->tcp);
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
	ip->tot_len = htons(sizeof(packet));
	/* TODO: Identification (check notes.txt) */
	ip->id = htonl(rand());
	/* IP Flags + Fragment offset TODO: Set don't fragment flag ! */
	ip->frag_off = 0;
	/* TTL */
	ip->ttl = 64;
	/* Protocol (TCP) */
	ip->protocol = IPPROTO_TCP;
	/* Checksum */
	ip->check = 0; /* Calculated after TCP header */
	/* Source ip */
	memcpy(&ip->saddr, &saddr->sin_addr.s_addr, sizeof(ip->saddr));
	/* Dest ip */
	memcpy(&ip->daddr, &daddr->sin_addr.s_addr, sizeof(ip->daddr));

	/* Source port */
	memcpy(&tcp->source, &saddr->sin_port, sizeof(tcp->source));
	/* Destination port */
	memcpy(&tcp->dest, &daddr->sin_port, sizeof(tcp->dest));
	/* Seq num */
	tcp->seq = htonl(0);
	/* Ack num */
	tcp->ack_seq = htonl(0);
	/* Sizeof header */
	tcp->doff = 5;
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
	tcp->check = tcp_checksum(ip, tcp);
	ip->check = checksum((const char*)packet, sizeof(packet));

	/* sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)daddr, sizeof(struct sockaddr)); */
	/* TODO: Error check */
	write(sockfd, packet, sizeof(packet));
	/* Make our cursor ready for read */
	update_cursor(sockfd, sizeof(packet));
}

static int sconfig(int sockfd, struct sockaddr_in *saddr)
{
	socklen_t addlen = sizeof(struct sockaddr);

	ft_memset(saddr, 0, sizeof(*saddr));

	saddr->sin_family = AF_INET;
	saddr->sin_port = htons(48866);
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

static int dconfig(char *destination, uint16_t port, struct sockaddr_in *daddr)
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

	printf("[*] Destination: %s (%s) on port: %d\n",
		destination, inet_ntoa(daddr->sin_addr), ntohs(daddr->sin_port));

	return 0;
}

static int read_syn_ack(int sockfd)
{
	int ret;
	fd_set set;
	struct timeval timeout = {5, 0};
	unsigned int len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	char buffer[len];
	struct tcp_packet *packet;

	FD_ZERO(&set); /* Init fd set */
	FD_SET(sockfd, &set);

	ret = select(sockfd+1, &set, NULL, NULL, &timeout);
	if (ret == -1) /* TODO: Select error handling */
		printf("Select error\n");
	else if (ret == 0)
		printf("Packet timeout\n");
	else {
		read(sockfd, buffer, len);
		packet = (struct tcp_packet *)buffer;
		/* TODO: Error checking ? */
		printf("[*] Received packet\n");
		print_ip4_header((struct ip *)&packet->ip);
		print_tcp_header(&packet->tcp);
	}

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
		fprintf(stderr, "%s: Failed to set header option\n", destination);
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
	read_syn_ack(sockfd);

	close(sockfd);
	return 0;
}

int ft_nmap(char *destination, uint16_t port, char *path)
{

	if (!destination) {
		fprintf(stderr, "%s: Empty hostname\n", path);
		return 1;
	}

	if (getuid() != 0) {
		fprintf(stderr, "%s: %s: Not allowed to create raw sockets, run as root\n",
			path, destination);
		return 1;
	}

	syn_scan(destination, port);

	return 0;
}
