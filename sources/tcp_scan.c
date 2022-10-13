#include "nmap.h"
#include "options.h"

static int send_syn(int sockfd, struct sockaddr_in *daddr)
{
	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Sending TCP request to: %s\n",
			inet_ntoa(daddr->sin_addr));

	/* Sending handcrafted packet */
	if (write(sockfd, "salut", 5) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to send TCP packet to: %s\n",
			inet_ntoa(daddr->sin_addr));
		return 1;
	}
	return 0;
}

static int read_tcp(int sockfd, struct s_scan *scan)
{
	int ret;
	int update_ret;
	int status = -1;
	char buffer[1];

	/* Receiving process */
	ret = recv(sockfd, buffer, sizeof(buffer), 0);

	/* Timed out */
	if (ret < 0)
		return TIMEOUT;

	status = OPEN;

	if (status != -1) {
		/* Update the corresponding scan if the recv packet is a response to one of our
		 * requests */
		if ((update_ret = update_scans(scan, status, scan->dport))) {
			if ((g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG))
			{
				fprintf(stderr, "[*] Received packet from %s with status: %d\n",
					inet_ntoa(scan->daddr->sin_addr), status);
			}
			/* The target scan has been updated */
			if (update_ret == UPDATE_TARGET)
				return 1;
		}
	}

	return 0;
}

int tcp_scan(struct s_scan *scan)
{
	int sockfd;
	struct timeval timeout = {1, 345678};
	int ret = 0;

	LOCK(scan);

	/* Prepare ports */
	scan->saddr->sin_port = htons(scan->sport);
	scan->daddr->sin_port = htons(scan->dport);

	/* Socket creation */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to create socket\n");
		scan->status = ERROR;
		UNLOCK(scan);
		return 1;
	}

	/* Set option */
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
	{
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to set timeout option\n");
		scan->status = ERROR;
		close(sockfd);
		UNLOCK(scan);
		return 1;
	}

	/* Scan start time */
	if ((gettimeofday(&scan->start_time, NULL)) != 0) {
		scan->start_time.tv_sec = 0;
		scan->start_time.tv_usec = 0;
	}

	/* Not authorized, remains a bonus */
	fcntl(sockfd, F_SETFL, O_NONBLOCK);

	/* Connect */
	/* TODO: Connect in loop, timeout invalid when returning here */
	if ((connect(sockfd, (struct sockaddr *)scan->daddr, sizeof(struct sockaddr)) != 0)) {
		scan->status = CLOSED;
		close(sockfd);
		UNLOCK(scan);
		return 1;
	}

	/* Scanning process */
	if (send_syn(sockfd, scan->daddr) != 0) {
		scan->status = ERROR;
		UNLOCK(scan);
	}
	else {
		UNLOCK(scan);
		while (!(ret = read_tcp(sockfd, scan)));
		/* We timed out, send the packet again */
		if (ret == TIMEOUT) {
			LOCK(scan);
			if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
				fprintf(stderr, "[*] TCP request on %s:%d timedout\n",
				inet_ntoa(scan->daddr->sin_addr), ntohs(scan->daddr->sin_port));
			/* Set the scan status to TIMEOUT, to inform we already timedout once */
			scan->status = TIMEOUT;
			/* Resend scan */
			if (send_syn(sockfd, scan->daddr) != 0) {
				scan->status = ERROR;
				UNLOCK(scan);
			}
			else {
				/* Successful send */
				UNLOCK(scan);
				while (!(ret = read_tcp(sockfd, scan)));
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
		fprintf(stderr, "[*] Updating %s:%d TCP's scan to %d\n",
		inet_ntoa(scan->daddr->sin_addr), ntohs(scan->daddr->sin_port),
		scan->status);

	close(sockfd);
	return 0;
}
