#include "nmap.h"
#include "options.h"

int		send_udp(int udpsockfd, struct sockaddr_in *saddr,
	struct sockaddr_in *daddr)
{
	unsigned int len = 0;
	char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + len];
	struct iphdr *ip = (struct iphdr*)packet;

	ft_memset(packet, 0, sizeof(packet));
	craft_ip_packet(packet, saddr, daddr, IPPROTO_UDP, NULL);
	/* TODO: Send specific payload for ports 53 and 161 */
	craft_udp_packet(packet, saddr, daddr, NULL, 0);

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG) {
		pthread_mutex_lock(&g_data.print_lock);
		fprintf(stderr, "[%ld] Sending UDP request to: %s:%d from port %d\n",
			pthread_self(), inet_ntoa(daddr->sin_addr), ntohs(daddr->sin_port),
			ntohs(saddr->sin_port));
		if (g_data.opt & OPT_VERBOSE_PACKET)
			print_ip4_header((struct ip *)ip);
		pthread_mutex_unlock(&g_data.print_lock);
	}

	/* Sending handcrafted packet */
	if (sendto(udpsockfd, packet, sizeof(packet), 0, (struct sockaddr *)daddr,
		sizeof(struct sockaddr)) < 0) {
		if (g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG) {
			pthread_mutex_lock(&g_data.print_lock);
			fprintf(stderr, "[%ld] Failed to send UDP packet to: %s:%d from port %d\n",
				pthread_self(), inet_ntoa(daddr->sin_addr), ntohs(daddr->sin_port),
				ntohs(saddr->sin_port));
			pthread_mutex_unlock(&g_data.print_lock);
		}
		return 1;
	}

	return 0;
}

static int read_udp(int udpsockfd, int icmpsockfd, struct s_scan *scan,
	struct timeval timeout, struct s_port *ports)
{
	ssize_t ret;
	int icmpret;
	int update_ret;
	int status = -1;
	unsigned int len = sizeof(struct icmp_packet);
	unsigned int icmp_len = sizeof(struct ip) + sizeof(struct icmphdr)
			+ sizeof(struct udp_packet);
	char buffer[len];
	char icmpbuffer[len];

	struct iphdr *ip;
	struct udp_packet *udp_packet;
	struct icmp_packet *icmp_packet;

	uint16_t dest = 0;
	uint16_t source = 0;

	/* Receiving process */
	ret = recv(udpsockfd, buffer, len, MSG_DONTWAIT);
	icmpret = recv(icmpsockfd, icmpbuffer, len, MSG_DONTWAIT);

	/* Handling timeout */
	if (timed_out(scan->start_time, timeout, scan->status))
			return TIMEOUT;

	/* Invalid packet (packet too small) */
	if (ret < (ssize_t)sizeof(struct udp_packet) &&
		icmpret < (ssize_t)icmp_len)
		return 0;

	if (ret >= (ssize_t)sizeof(struct udp_packet)) {
		ip = (struct iphdr *)buffer;
		//printf("UDP!!\n");
		if (ip->protocol == IPPROTO_UDP) {
			status = OPEN;
			udp_packet = (struct udp_packet *)buffer;
			dest = udp_packet->udp.uh_dport;
			source = udp_packet->udp.uh_sport;
		}
	}
	if (icmpret >= (ssize_t)icmp_len) {
		ip = (struct iphdr *)icmpbuffer;
		if (ip->protocol == IPPROTO_ICMP) {
			icmp_packet = (struct icmp_packet *)icmpbuffer;
			/* TODO: Add delay to not spam hosts */
			/*printf("ICMP type %d code %d!!\n",
			icmp_packet->icmp.type, icmp_packet->icmp.code);
			print_ip4_header((struct ip*)&icmp_packet->ip);*/
			if (icmp_packet->icmp.type == ICMP_DEST_UNREACH) {
				if (icmp_packet->icmp.code == ICMP_PORT_UNREACH)
					status = CLOSED;
				else
					status = FILTERED;
			}
			udp_packet = (struct udp_packet*)&(icmp_packet->udp);
			//print_ip4_header((struct ip*)&udp_packet->ip);
			dest = udp_packet->udp.uh_sport;
			source = udp_packet->udp.uh_dport;
		}
	}

	if (status != -1) {
		/* Update the corresponding scan if the recv packet is a response to one of our
		 * requests */
		if ((update_ret = update_scans(scan, ports, status,
			dest, source)))
		{
			if ((g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG))
			{
				pthread_mutex_lock(&g_data.print_lock);
				fprintf(stderr, "[%ld] Received packet from %s:%d with status: %d\n",
					pthread_self(), inet_ntoa(*(struct in_addr*)&ip->saddr),
					ntohs(udp_packet->udp.uh_sport),
					status);
				if (g_data.opt & OPT_VERBOSE_PACKET)
					print_ip4_header((struct ip *)&udp_packet->ip);
				pthread_mutex_unlock(&g_data.print_lock);
			}
			/* The target scan has been updated */
			if (update_ret == UPDATE_TARGET)
				return 1;
		}
	}

	return 0;
}

int		udp_scan(struct s_scan *scan, struct s_port *ports)
{
	int	udpsockfd;
	int	icmpsockfd;
	int ret;
	struct timeval timeout = {1, 345678};

	//printf("UDP scan\n");

	LOCK(scan);

	/* Socket creation */
	if ((udpsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET) {
			pthread_mutex_lock(&g_data.print_lock);
			fprintf(stderr, "[%ld] Failed to create socket\n", pthread_self());
			pthread_mutex_unlock(&g_data.print_lock);
		}
		scan->status = ERROR;
		UNLOCK(scan);
		return 1;
	}

	/* Set options */
	int one = 1;
	if ((setsockopt(udpsockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET) {
			pthread_mutex_lock(&g_data.print_lock);
			fprintf(stderr, "[%ld] Failed to set header option\n", pthread_self());
			pthread_mutex_unlock(&g_data.print_lock);
		}
		scan->status = ERROR;
		close(udpsockfd);
		UNLOCK(scan);
		return 1;
	}

	/* ICMP Socket creation */
	if ((icmpsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET) {
			pthread_mutex_lock(&g_data.print_lock);
			fprintf(stderr, "[%ld] Failed to create ICMP socket\n", pthread_self());
			pthread_mutex_unlock(&g_data.print_lock);
		}
		scan->status = ERROR;
		UNLOCK(scan);
		return 1;
	}

	/* Set options */
	if ((setsockopt(icmpsockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET) {
			pthread_mutex_lock(&g_data.print_lock);
			fprintf(stderr, "[%ld] Failed to set header option\n", pthread_self());
			pthread_mutex_unlock(&g_data.print_lock);
		}
		scan->status = ERROR;
		close(udpsockfd);
		close(udpsockfd);
		UNLOCK(scan);
		return 1;
	}

	/* Scan start time */
	if ((gettimeofday(&scan->start_time, NULL)) != 0) {
		scan->start_time.tv_sec = 0;
		scan->start_time.tv_usec = 0;
	}

	/* Service assignation */
	scan->service = g_data.ports[scan->dport].udp_name;
	scan->service_desc = g_data.ports[scan->dport].udp_desc;

	/* Scanning process */
	ret = 0;
	if (send_udp(udpsockfd, &scan->saddr, &scan->daddr) != 0) {
		scan->status = ERROR;
		UNLOCK(scan);
	}
	else {
		UNLOCK(scan);
		while (!(ret = read_udp(udpsockfd, icmpsockfd, scan, timeout, ports)));
		/* We timed out, send the packet again */
		if (ret == TIMEOUT) {
			LOCK(scan);
			if (g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG) {
				pthread_mutex_lock(&g_data.print_lock);
				fprintf(stderr, "[%ld] UDP request on %s:%d timedout\n", pthread_self(),
					inet_ntoa(scan->daddr.sin_addr), ntohs(scan->daddr.sin_port));
				pthread_mutex_unlock(&g_data.print_lock);
			}
			/* Set the scan status to TIMEOUT, to inform we already timedout once */
			scan->status = TIMEOUT;
			/* Resend scan */
			if (send_udp(udpsockfd, &scan->saddr, &scan->daddr) != 0) {
				scan->status = ERROR;
				UNLOCK(scan);
			}
			else {
				/* Successful send */
				UNLOCK(scan);
				while (!(ret = read_udp(udpsockfd, icmpsockfd, scan,
					timeout, ports)));
				/* Another timeout, set the status to filtered */
				if (ret == TIMEOUT) {
					LOCK(scan);
					scan->status = OPEN_FILTERED;
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

	if (g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG) {
		pthread_mutex_lock(&g_data.print_lock);
		char *status[] = {
			"OPEN", "CLOSED", "FILTERED", "OPEN|FILTERED", "UNFILTERED", NULL
		};
		fprintf(stderr, "[%ld] Updating %s:%d UDP scan to %s\n", pthread_self(),
		inet_ntoa(scan->daddr.sin_addr), ntohs(scan->daddr.sin_port),
		status[scan->status]);
		pthread_mutex_unlock(&g_data.print_lock);
	}

	close(icmpsockfd);
	close(udpsockfd);
	return 0;
}
