#include "nmap.h"
#include "options.h"

static int send_syn(int sockfd,
	struct sockaddr_in *saddr, struct sockaddr_in *daddr)
{
	unsigned int len = 0;

	char packet[sizeof(struct iphdr)+sizeof(struct tcphdr)+len];
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
	ip->frag_off = 0;
	/* TTL */
	ip->ttl = 64;
	/* Protocol (TCP) */
	ip->protocol = IPPROTO_TCP;
	/* Checksum */
	ip->check = 0; /* Calculated after TCP header */
	/* Source ip */
	ft_memcpy(&ip->saddr, &saddr->sin_addr.s_addr, sizeof(ip->saddr));
	/* Dest ip */
	ft_memcpy(&ip->daddr, &daddr->sin_addr.s_addr, sizeof(ip->daddr));

	/* Filling TCP header */
	/* Source port */
	ft_memcpy(&tcp->source, &saddr->sin_port, sizeof(tcp->source));
	/* Destination port */
	ft_memcpy(&tcp->dest, &daddr->sin_port, sizeof(tcp->dest));
	/* Seq num */
	tcp->seq = htons(0);
	/* Ack num */
	tcp->ack_seq = htons(0);
	/* Sizeof header / 4 */
	tcp->doff = sizeof(struct tcphdr) /  4;
	/* Flags */
	tcp->fin = 0;
	tcp->syn = 1;
	tcp->rst = 0;
	tcp->psh = 0;
	tcp->ack = 0;
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

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Sending SYN request to: %s:%d from port %d\n",
			inet_ntoa(daddr->sin_addr), ntohs(daddr->sin_port),
			ntohs(saddr->sin_port));

	if (g_data.opt & OPT_VERBOSE_DEBUG)
		print_ip4_header((struct ip *)ip);

	/* Sending handcrafted packet */
	if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)daddr,
		sizeof(struct sockaddr)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to send SYN packet to: %s:%d from port %d\n",
			inet_ntoa(daddr->sin_addr), ntohs(daddr->sin_port),
			ntohs(saddr->sin_port));
		return 1;
	}

	return 0;
}

static int timed_out(struct timeval start, struct timeval timeout, int status)
{
	struct timeval end;
	long long start_ms;
	long long end_ms;
	long long to_ms;

	/* Request end time */
	if ((gettimeofday(&end, NULL)) != 0) {
		end.tv_sec = 0;
		end.tv_usec = 0;
	}

	start_ms = start.tv_sec*1000 + start.tv_usec/1000;
	end_ms = end.tv_sec*1000 + end.tv_usec/1000;
	to_ms = timeout.tv_sec*1000 + timeout.tv_usec/1000;

	/* If we already timedout, the timer for timeout should be *2 */
	if (status == TIMEOUT)
		to_ms *= 2;

	if (end_ms - start_ms > to_ms)
		return 1;

	return 0;
}

static int read_syn_ack(int sockfd, struct s_scan *scan, struct timeval timeout)
{
	int ret;
	int update_ret;
	int status = -1;
	unsigned int len = sizeof(struct icmp_packet);
	char buffer[len];

	struct iphdr *ip;
	struct tcp_packet *packet;
	struct icmp_packet *epacket;

	uint16_t dest;

	/* Check if another thread already updated the scan status */
	if (scan->status != TIMEOUT && scan->status != SCANNING)
		return ALREADY_UPDATED;

	/* Receiving process */
	ret = recv(sockfd, buffer, len, MSG_DONTWAIT);

	/* Handling timeout */
	if (timed_out(scan->start_time, timeout, scan->status))
			return TIMEOUT;

	/* Invalid packet (packet too small) */
	if (ret < (int)sizeof(struct tcp_packet) &&
		ret < (int)sizeof(struct icmp_packet))
		return 0;

	/* TODO: Packet error checking ? */
	ip = (struct iphdr *)buffer;
	if (ip->protocol == IPPROTO_TCP) {
		packet = (struct tcp_packet *)buffer;
		dest = packet->tcp.dest;
		if (packet->tcp.rst)
			status = CLOSED;
		else if (packet->tcp.ack && packet->tcp.syn)
			status = OPEN;
	}
	else if (ip->protocol == IPPROTO_ICMP) {
		epacket = (struct icmp_packet *)buffer;
		if (epacket->icmp.type == ICMP_DEST_UNREACH)
			status = FILTERED;
		packet = &(epacket->data);
		dest = packet->tcp.source;
	}

	if (status != -1) {
		/* Update the corresponding scan if the recv packet is a response to one of our
		 * requests */
		if ((update_ret = update_scans(scan, status, dest))) {
			if ((g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG))
			{
				fprintf(stderr, "[*] Received packet from %s:%d with status: %d\n",
					inet_ntoa(*(struct in_addr*)&ip->saddr),
					ntohs(packet->tcp.source),
					status);
				if (g_data.opt & OPT_VERBOSE_DEBUG)
					print_ip4_header((struct ip *)&packet->ip);
			}
			/* The target scan has been updated */
			if (update_ret == UPDATE_TARGET)
				return 1;
		}
	}

	return 0;
}

int syn_scan(struct s_scan *scan)
{
	int sockfd;
	struct timeval timeout = {1, 345678};
	struct servent *s_service;
	char *service = "unknown";
	int ret = 0;

	LOCK(scan);

	/* Prepare ports */
	scan->saddr->sin_port = htons(scan->sport);
	scan->daddr->sin_port = htons(scan->dport);

	/* Socket creation */
	/*if ((sockfd = socket(AF_PACKET, SOCK_RAW, ETH_P_IP)) < 0) {*/
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to create socket\n");
		scan->status = ERROR;
		UNLOCK(scan);
		return 1;
	}

	/* Set options */
	int one = 1;
	if ((setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to set header option\n");
		scan->status = ERROR;
		close(sockfd);
		UNLOCK(scan);
		return 1;
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		sizeof(timeout)) != 0)
	{
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to set timeout option\n");
		scan->status = ERROR;
		close(sockfd);
		UNLOCK(scan);
		return 1;
	}

	/* Service detection */
	/* Network services database file /etc/services */
	if ((s_service = getservbyport(scan->daddr->sin_port, NULL)))
		service = s_service->s_name;
	scan->service = ft_strdup(service);

	/* Scan start time */
	if ((gettimeofday(&scan->start_time, NULL)) != 0) {
		scan->start_time.tv_sec = 0;
		scan->start_time.tv_usec = 0;
	}

	/* Scanning process */
	if (send_syn(sockfd, scan->saddr, scan->daddr) != 0) {
		scan->status = ERROR;
		UNLOCK(scan);
	}
	else {
		UNLOCK(scan);
		while (!(ret = read_syn_ack(sockfd, scan, timeout)));
		/* We timed out, send the packet again */
		if (ret == TIMEOUT) {
			LOCK(scan);
			if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
				fprintf(stderr, "[*] SYN request on %s:%d timedout\n",
				inet_ntoa(scan->daddr->sin_addr), ntohs(scan->daddr->sin_port));
			/* Set the scan status to TIMEOUT, to inform we already timedout once */
			scan->status = TIMEOUT;
			/* Resend scan */
			if (send_syn(sockfd, scan->saddr, scan->daddr) != 0) {
				scan->status = ERROR;
				UNLOCK(scan);
			}
			else {
				/* Successful send */
				UNLOCK(scan);
				while (!(ret = read_syn_ack(sockfd, scan, timeout)));
				/* Another timeout, set the status to filtered */
				if (ret == TIMEOUT) {
					LOCK(scan);
					scan->status = FILTERED;
					UNLOCK(scan);
				}
			}
		}
	}

	/* Scan end time */
	if ((gettimeofday(&scan->end_time, NULL)) != 0) {
		scan->end_time.tv_sec = 0;
		scan->end_time.tv_usec = 0;
	}

	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Updating %s:%d SYN's scan to %d\n",
		inet_ntoa(scan->daddr->sin_addr), ntohs(scan->daddr->sin_port),
		scan->status);

	close(sockfd);
	return 0;
}
