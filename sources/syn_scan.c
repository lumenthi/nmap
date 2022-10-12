#include "nmap.h"
#include "options.h"

static int send_syn(int sockfd,
	struct sockaddr_in *saddr, struct sockaddr_in *daddr)
{
	unsigned int len = 0;

	char packet[sizeof(struct iphdr)+sizeof(struct tcphdr)+len];
	struct iphdr *ip = (struct iphdr *)packet;

	craft_ip_packet(packet, saddr, daddr, IPPROTO_TCP, NULL);
	craft_tcp_packet(packet, saddr, daddr, TH_SYN, NULL);

	/* Checksum */
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
	ssize_t ret;
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
	ret = recv(sockfd, buffer, len, 0);

	//printf("received %ld\n", ret);
	/* Handling timeout */
	if (timed_out(scan->start_time, timeout, scan->status))
			return TIMEOUT;

	/* Invalid packet (packet too small) */
	if (ret < (ssize_t)sizeof(struct tcp_packet) &&
		ret < (ssize_t)sizeof(struct icmp_packet))
	{
		//printf("Ret too small\n");
		return 0;
	}

	/* TODO: Packet error checking ? */
	ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	if (ip->protocol == IPPROTO_TCP) {
		//printf("TCP\n");
		packet = (struct tcp_packet *)buffer;
		dest = packet->tcp.dest;
		if (packet->tcp.rst)
			status = CLOSED;
		else if (packet->tcp.ack || packet->tcp.syn)
			status = OPEN;
	}
	else if (ip->protocol == IPPROTO_ICMP) {
		printf("ICMP!!!\n");
		epacket = (struct icmp_packet *)buffer;
		//print_ip4_header((struct ip*)ip);
		print_icmp_header(&epacket->icmp);
		if (epacket->icmp.type == ICMP_DEST_UNREACH)
		{
			printf("Filtered!\n");
			status = FILTERED;
		}
		packet = &(epacket->data);
		//print_tcp_header(&packet->tcp);
		print_tcp_header((struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct ip) + sizeof(struct icmp) + sizeof(struct ip)));
		//print_ip4_header((struct ip*)&packet->ip);
		dest = packet->tcp.source;
	}

	//printf("Status = %d\n", status);
	//printf("OPEN = %d\n", OPEN);
	//printf("CLOSED = %d\n", CLOSED);
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
	int sockfd, recvfd;
	struct timeval timeout = {1, 345678};
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

	if ((recvfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to create socket\n");
		scan->status = ERROR;
		UNLOCK(scan);
		return 1;
	}

	/*struct sock_filter BPF_code[] = {
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 1, 0x00000800 },
		{ 0x6, 0, 0, 0x00040000 },
		{ 0x6, 0, 0, 0x00000000 }
	};    
	struct sock_fprog Filter;
	// error prone code, .len field should be consistent with the real length of the filter code array
	Filter.len = sizeof(BPF_code)/sizeof(BPF_code[0]); 
	Filter.filter = BPF_code;

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &Filter, sizeof(Filter)) < 0) {
		perror("setsockopt attach filter");
		close(sock);
			exit(1);
	}*/

	/* Set options */
	int one = 1;
	if ((setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to set header option\n");
		scan->status = ERROR;
		close(sockfd);
		close(recvfd);
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
		close(recvfd);
		UNLOCK(scan);
		return 1;
	}

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
		while (!(ret = read_syn_ack(recvfd, scan, timeout)));
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
				while (!(ret = read_syn_ack(recvfd, scan, timeout)));
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
	close(recvfd);
	return 0;
}
