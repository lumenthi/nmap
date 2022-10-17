#include "nmap.h"
#include "options.h"

static int send_syn(int tcpsockfd,
	struct sockaddr_in *saddr, struct sockaddr_in *daddr)
{
	unsigned int len = 0;

	char packet[sizeof(struct iphdr)+sizeof(struct tcphdr)+len];
	struct iphdr *ip = (struct iphdr *)packet;

	ft_memset(packet, 0, sizeof(packet));
	craft_ip_packet(packet, saddr, daddr, IPPROTO_TCP, NULL);
	craft_tcp_packet(packet, saddr, daddr, TH_SYN, NULL);

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Sending SYN request to: %s:%d from port %d\n",
			inet_ntoa(daddr->sin_addr), ntohs(daddr->sin_port),
			ntohs(saddr->sin_port));

	if (g_data.opt & OPT_VERBOSE_DEBUG)
		print_ip4_header((struct ip *)ip);

	/* Sending handcrafted packet */
	if (sendto(tcpsockfd, packet, sizeof(packet), 0, (struct sockaddr *)daddr,
		sizeof(struct sockaddr)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to send SYN packet to: %s:%d from port %d\n",
			inet_ntoa(daddr->sin_addr), ntohs(daddr->sin_port),
			ntohs(saddr->sin_port));
		return 1;
	}

	return 0;
}

static int read_syn_ack(int tcpsockfd, int icmpsockfd, struct s_scan *scan,
	struct timeval timeout)
{
	int ret;
	int icmpret;
	int update_ret;
	int status = -1;
	unsigned int len = sizeof(struct icmp_packet);
	unsigned int icmp_len = sizeof(struct ip) + sizeof(struct icmphdr)
		+ sizeof(struct tcp_packet);
	char buffer[len];
	char icmpbuffer[len];

	struct iphdr *ip;
	struct tcp_packet *tcp_packet;
	struct icmp_packet *icmp_packet;

	uint16_t dest;

	/* Check if another thread already updated the scan status */
	if (scan->status != TIMEOUT && scan->status != SCANNING)
		return ALREADY_UPDATED;

	/* Receiving process */
	ret = recv(tcpsockfd, buffer, len, MSG_DONTWAIT);
	icmpret = recv(icmpsockfd, icmpbuffer, len, MSG_DONTWAIT);

	/* Handling timeout */
	if (timed_out(scan->start_time, timeout, scan->status))
			return TIMEOUT;

	/* Invalid packet (packet too small) */
	if (ret < (ssize_t)sizeof(struct tcp_packet) &&
		icmpret < (ssize_t)icmp_len)
		return 0;

	/* TODO: Packet error checking ? */
	if (ret >= (ssize_t)sizeof(struct tcp_packet)) {
		ip = (struct iphdr *)buffer;
		if (ip->protocol == IPPROTO_TCP) {
			tcp_packet = (struct tcp_packet *)buffer;
			dest = tcp_packet->tcp.dest;
			if (tcp_packet->tcp.rst)
				status = CLOSED;
			else if (tcp_packet->tcp.ack && tcp_packet->tcp.syn)
				status = OPEN;
		}
	}
	if (icmpret >= (ssize_t)icmp_len) {
		ip = (struct iphdr *)icmpbuffer;
		if (ip->protocol == IPPROTO_ICMP) {
			icmp_packet = (struct icmp_packet *)icmpbuffer;
			if (icmp_packet->icmp.type == ICMP_DEST_UNREACH)
				status = FILTERED;
			tcp_packet = (struct tcp_packet*)&(icmp_packet->tcp);
			dest = tcp_packet->tcp.source;
		}
	}

	if (status != -1) {
		/* Update the corresponding scan if the recv packet is a response to one of our
		 * requests */
		if ((update_ret = update_scans(scan, status, dest, OPT_SCAN_SYN))) {
			if ((g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG))
			{
				fprintf(stderr, "[*] Received packet from %s:%d with status: %d\n",
					inet_ntoa(*(struct in_addr*)&ip->saddr),
					ntohs(tcp_packet->tcp.source),
					status);
				if (g_data.opt & OPT_VERBOSE_DEBUG)
					print_ip4_header((struct ip *)&tcp_packet->ip);
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
	int tcpsockfd;
	int icmpsockfd;
	int ret;
	struct timeval timeout = {1, 345678};

	LOCK(scan);

	/* Prepare ports */
	scan->saddr->sin_port = htons(scan->sport);
	scan->daddr->sin_port = htons(scan->dport);

	/* Socket creation */
	if ((tcpsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to create socket\n");
		scan->status = ERROR;
		UNLOCK(scan);
		return 1;
	}
	/* Set options */
	int one = 1;
	if ((setsockopt(tcpsockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to set header option\n");
		scan->status = ERROR;
		close(tcpsockfd);
		UNLOCK(scan);
		return 1;
	}

	/* ICMP Socket creation */
	if ((icmpsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to create ICMP socket\n");
		scan->status = ERROR;
		close(tcpsockfd);
		close(icmpsockfd);
		UNLOCK(scan);
		return 1;
	}
	/* Set options */
	if ((setsockopt(icmpsockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to set header option\n");
		scan->status = ERROR;
		close(tcpsockfd);
		close(icmpsockfd);
		UNLOCK(scan);
		return 1;
	}

	/* Scan start time */
	if ((gettimeofday(&scan->start_time, NULL)) != 0) {
		scan->start_time.tv_sec = 0;
		scan->start_time.tv_usec = 0;
	}

	/* Scanning process */
	ret = 0;
	if (send_syn(tcpsockfd, scan->saddr, scan->daddr) != 0) {
		scan->status = ERROR;
		UNLOCK(scan);
	}
	else {
		UNLOCK(scan);
		while (!(ret = read_syn_ack(tcpsockfd, icmpsockfd, scan, timeout)));
		/* We timed out, send the packet again */
		if (ret == TIMEOUT) {
			LOCK(scan);
			if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
				fprintf(stderr, "[*] SYN request on %s:%d timedout\n",
				inet_ntoa(scan->daddr->sin_addr), ntohs(scan->daddr->sin_port));
			/* Set the scan status to TIMEOUT, to inform we already timedout once */
			scan->status = TIMEOUT;
			/* Resend scan */
			if (send_syn(tcpsockfd, scan->saddr, scan->daddr) != 0) {
				scan->status = ERROR;
				UNLOCK(scan);
			}
			else {
				/* Successful send */
				UNLOCK(scan);
				while (!(ret = read_syn_ack(tcpsockfd, icmpsockfd, scan, timeout)));
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

	char *status[] = {
		"OPEN", "CLOSED", "FILTERED", "OPEN|FILTERED", "UNFILTERED", NULL 
	};
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG) {
		fprintf(stderr, "[*] Updating %s:%d SYN scan to %s\n",
		inet_ntoa(scan->daddr->sin_addr), ntohs(scan->daddr->sin_port),
		status[scan->status]);
	}

	close(icmpsockfd);
	close(tcpsockfd);
	return 0;
}
