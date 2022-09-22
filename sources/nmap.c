#include "nmap.h"

static int resolve(char *host, t_data *g_data)
{
	struct addrinfo hints;

	if (!ft_memset(&hints, 0, sizeof(struct addrinfo)))
		return 1;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	/* Subject to any restrictions imposed by hints */
	if (getaddrinfo(host, NULL, &hints, &g_data->host_info) == -1 ||
		g_data->host_info == NULL)
		return 1;

	g_data->host_addr = g_data->host_info->ai_addr;
	g_data->servaddr = *(struct sockaddr_in *)g_data->host_addr;

	ft_strncpy(g_data->ipv4, inet_ntoa(g_data->servaddr.sin_addr),
		sizeof(g_data->ipv4));

	return 0;
}

static unsigned short csum(unsigned short *buf, int len)
{
	unsigned long sum;

	for(sum=0; len>0; len--)
		sum += *buf++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

static void send_syn(int sockfd, t_data *g_data)
{
	unsigned int len = 0;

	char packet[sizeof(struct iphdr)+sizeof(struct tcphdr)+len];
	struct iphdr *ip = (struct iphdr *)packet;
	struct tcphdr *tcp = (struct tcphdr *)(packet+sizeof(struct iphdr));
	(void)g_data;

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
	ip->id = htons(56508);
	/* TODO: Set don't fragment flag ! IP Flags + Fragment offset */
	ip->frag_off = 0;
	/* TTL */
	ip->ttl = 64;
	/* Protocol (TCP) */
	ip->protocol = IPPROTO_TCP;
	/* Checksum */
	ip->check = 0; /* TODO: Calculate it after the TCP header */
	/* Source ip */
	ip->saddr = *(uint32_t *)&g_data->servaddr.sin_addr;
	/* Dest ip */
	ip->daddr = *(uint32_t *)&g_data->servaddr.sin_addr;

	/* Source port */
	tcp->source = htons(57686);
	/* Destination port */
	tcp->dest = *(uint16_t *)&g_data->servaddr.sin_addr;
	/* Seq num */
	tcp->seq = htonl(1);
	/* Ack num */
	tcp->ack_seq = 0;
	/* Sizeof header */
	tcp->doff = 10;
	/* SYN */
	tcp->syn = 1;
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

	sendto(sockfd, packet, ip->tot_len, 0, g_data->host_addr, sizeof(struct sockaddr_in));
	write(sockfd, packet, sizeof(packet));
}

int syn_scan(char *destination, uint16_t port)
{
	(void)port;
	t_data g_data = {0};
	int sockfd;
	int one = 1;

	/* Socket creation */
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		fprintf(stderr, "%s: Failed to create TCP socket\n", destination);
		return 1;
	}

	/* Resolving host */
	if (resolve(destination, &g_data)) {
		fprintf(stderr, "%s: Name or service not known\n", destination);
		close(sockfd);
		return 1;
	} /* g_data.host_info is allocated ! Must free it now */

	/* Set options */
	if ((setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		fprintf(stderr, "%s: Failed to set TTL option\n", destination);
		freeaddrinfo(g_data.host_info);
		close(sockfd);
		return 1;
	}

	g_data.servaddr.sin_family = AF_INET;
	g_data.servaddr.sin_port = htons(port);
	g_data.host_addr = (struct sockaddr *)&g_data.servaddr;

	/* int ret = connect(sockfd, g_data.host_addr, sizeof(g_data.servaddr));
	if (ret != 0) {
		fprintf(stderr, "%s: Failed to connect to host\n", destination);
		freeaddrinfo(g_data.host_info);
		close(sockfd);
		return 1;
	}*/ 

	send_syn(sockfd, &g_data);

	printf("%s: %s\n", destination, g_data.ipv4);

	freeaddrinfo(g_data.host_info);
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
