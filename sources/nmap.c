#include "nmap.h"
#include "options.h"

static int ft_random(int min, int max)
{
	int fd = open("/dev/urandom", O_RDONLY);
	int data = -1;

	if (fd < 0)
		return -1;
	else {
		while (data < min || data > max) {
			read(fd, &data, 2);
			data *= data < 0 ? -1 : 1;
		}
	}
	close(fd);
	return data;
}

static unsigned short checksum(const char *buf, unsigned int size)
{
	unsigned sum = 0, i;

	/* Accumulate checksum */
	for (i = 0; i < size - 1; i += 2) {
		unsigned short word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}

	/* Handle odd-sized case */
	if (size & 1) {
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

static void update_cursor(int sockfd, unsigned int len, int sport)
{
	char buffer[len];
	struct tcp_packet *packet;
	int pport = -1;

	while (pport != sport) {
		// printf("sport: %d, pport: %d\n", sport, pport);
		if (recv(sockfd, buffer, len, MSG_DONTWAIT) < 0)
			return;
		packet = (struct tcp_packet *)buffer;
		pport = packet->tcp.source;
	}
}

static int send_syn(int sockfd,
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
	ip->id = htons(ft_random(0, 600));
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
	tcp->seq = htons(0);
	/* Ack num */
	tcp->ack_seq = htons(0);
	/* Sizeof header / 4 */
	/* TODO: Options handling */
	tcp->doff = sizeof(struct tcphdr) /  4;
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

	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		printf("[*] Ready to send SYN packet...\n");
	/* TODO: Error check */
	sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)daddr, sizeof(struct sockaddr));
	if (ip->saddr == ip->daddr)
		update_cursor(sockfd, sizeof(packet), tcp->source);
	if (g_data.opt & OPT_VERBOSE_DEBUG) {
		print_ip4_header((struct ip *)ip);
		print_tcp_header(tcp);
	}
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		printf("[*] Sent SYN packet\n");
	return 0;
}

static int sconfig(char *destination, struct sockaddr_in *saddr)
{
	struct ifaddrs *addrs;
	struct ifaddrs *tmp;

	ft_memset(saddr, 0, sizeof(*saddr));

	saddr->sin_family = AF_INET;
	/* Ephemeral Port Range, /proc/sys/net/ipv4/ip_local_port_range */
	/* TODO: Read port range ? */
	saddr->sin_port = htons(ft_random(32768, 60999));

	if (!ft_strcmp(destination, "127.0.0.1")) {
		if (inet_pton(AF_INET, "127.0.0.1", &(saddr->sin_addr)) != 1)
			return 1;
	}
	else {
		/* TODO: Error handling no/invalid interfaces & returns check */
		getifaddrs(&addrs);
		tmp = addrs;
		while (tmp)
		{
			if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
			{
				struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
				// printf("%s: %s\n", tmp->ifa_name, inet_ntoa(pAddr->sin_addr));
				/* TODO: Recognition of good interface */
				if (!(tmp->ifa_flags & IFF_LOOPBACK)) {
					/* TODO: Check if null ? | Error check */
					if (inet_pton(AF_INET, inet_ntoa(pAddr->sin_addr), &(saddr->sin_addr)) != 1) {
						freeifaddrs(addrs);
						return 1;
					}
					break ;
				}
			}
			tmp = tmp->ifa_next;
		}
		freeifaddrs(addrs);
	}

	printf("[*] Source: %s on port: %d\n",
		inet_ntoa(saddr->sin_addr), ntohs(saddr->sin_port));

	return 0;
}

static int dconfig(char *destination, uint16_t port, struct sockaddr_in *daddr)
{
	struct hostent *host;

	ft_memset(daddr, 0, sizeof(*daddr));
	if (!(host = gethostbyname(destination)))
		return 1;

	daddr->sin_family = host->h_addrtype;
	daddr->sin_port = htons(port);
	ft_memcpy(&(daddr->sin_addr.s_addr), host->h_addr_list[0], host->h_length);

	printf("[*] Destination: %s (%s) on port: %d\n",
		host->h_name, inet_ntoa(daddr->sin_addr), ntohs(daddr->sin_port));

	return 0;
}

static int read_syn_ack(int sockfd)
{
	int ret;
	unsigned int len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	char buffer[len];
	struct tcp_packet *packet;

	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		printf("[*] Ready to receive...\n");
	ret = recv(sockfd, buffer, len, 0);
	if (ret < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			printf("[*] Packet timeout\n");
		return TIMEOUT;
	}
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		printf("[*] Received packet\n");
	if (ret < (int)sizeof(struct tcp_packet))
		return ERROR;
	packet = (struct tcp_packet *)buffer;
	/* TODO: Error checking ? */
	if (g_data.opt & OPT_VERBOSE_DEBUG) {
		print_ip4_header((struct ip *)&packet->ip);
		print_tcp_header(&packet->tcp);
	}

	if (packet->tcp.rst)
		return CLOSED;

	if (packet->tcp.ack && packet->tcp.syn)
		return OPEN;

	/* TODO: ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13) */
	return FILTERED;
}

int syn_scan(char *destination, uint16_t port)
{
	int sockfd;
	int one = 1;
	struct sockaddr_in saddr;
	struct sockaddr_in daddr;
	/* TODO: Real timeout ? */
	struct timeval timeout = {1, 533000};
	int ret;
	struct servent *s_service;
	char *service = "unknown";

	if (dconfig(destination, port, &daddr) != 0) {
		fprintf(stderr, "%s: Name or service not known\n", destination);
		return DOWN;
	}

	/* Socket creation */
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		fprintf(stderr, "%s: Failed to create TCP socket\n", destination);
		return ERROR;
	}

	/* Set options */
	if ((setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		fprintf(stderr, "%s: Failed to set header option\n", destination);
		close(sockfd);
		return ERROR;
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		sizeof(timeout)) != 0)
	{
		fprintf(stderr, "%s: Failed to set timeout option\n", destination);
		close(sockfd);
		return ERROR;
	}

	if (sconfig(inet_ntoa(daddr.sin_addr), &saddr)) {
		fprintf(stderr, "%s: Source configuration failed\n", destination);
		close(sockfd);
		return ERROR;
	}

	if ((connect(sockfd, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) != 0)) {
		fprintf(stderr, "%s: Failed to connect to host\n", destination);
		close(sockfd);
		return ERROR;
	}

	/* Service detection */
	/* Network services database file /etc/services */
	if ((s_service = getservbyport(htons(port), NULL)))
		service = s_service->s_name;

	printf("[*] Found service: %s\n", service);

	/* TODO: Error check */
	send_syn(sockfd, &saddr, &daddr);
	if ((ret = read_syn_ack(sockfd)) == TIMEOUT) {
		send_syn(sockfd, &saddr, &daddr);
		if ((ret = read_syn_ack(sockfd)) == TIMEOUT)
			return FILTERED;
	}

	close(sockfd);
	return ret;
}

int ft_nmap(char *destination, uint16_t port, char *path)
{
	int ret;
	char *status[] = {"OPEN",
		"CLOSED", "FILTERED", "DOWN", "ERROR"};

	if (!destination) {
		fprintf(stderr, "%s: Empty hostname\n", path);
		return 1;
	}

	if (getuid() != 0) {
		fprintf(stderr, "%s: %s: Not allowed to create raw sockets, run as root\n",
			path, destination);
		return 1;
	}

	ret = syn_scan(destination, port);
	printf("[*] SYN scan result: %s\n", status[ret]);

	return 0;
}
