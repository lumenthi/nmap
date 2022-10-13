#include "nmap.h"
#include "options.h"

/* TODO: Do not assign source ports to TCP scans, its useless */
int tcp_scan(struct s_scan *scan)
{
	int sockfd;
	int err;
	int len = sizeof(err);
	int i = 0;
	struct timeval timeout;

	/* Prepare ports */
	scan->saddr->sin_port = htons(scan->sport);
	scan->daddr->sin_port = htons(scan->dport);

	/* Socket creation */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to create socket\n");
		scan->status = ERROR;
		return 1;
	}

	/* Not authorized, remains a bonus */
	if (fcntl(sockfd, F_SETFL, O_NONBLOCK) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[!] Failed to set fcntl option\n");
		scan->status = ERROR;
		close(sockfd);
		return 1;
	}

	/* Scan start time */
	if ((gettimeofday(&scan->start_time, NULL)) != 0) {
		scan->start_time.tv_sec = 0;
		scan->start_time.tv_usec = 0;
	}

	/* Setting read fds for select */
	fd_set rfds;
	FD_ZERO(&rfds);

	/* Setting listen fds for select */
	fd_set lfds;
	FD_ZERO(&lfds);

	/* Setting exception fds for select */
	fd_set efds;
	FD_ZERO(&efds);

	/* Default status */
	scan->status = FILTERED;
	while (i < 2) {
		timeout.tv_sec = 1;
		timeout.tv_usec = 345678;
		FD_SET(sockfd, &rfds);
		FD_SET(sockfd, &lfds);
		FD_SET(sockfd, &efds);
		connect(sockfd, (struct sockaddr *)scan->daddr, sizeof(struct sockaddr));
		getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char*)&err, (socklen_t *)&len);
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[*] Sent TCP request to %s:%d\n",
				inet_ntoa(scan->daddr->sin_addr), ntohs(scan->daddr->sin_port));
		if (err == ECONNREFUSED) {
			if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
				fprintf(stderr, "[*] Received TCP [CLOSED] response from %s:%d\n",
					inet_ntoa(scan->daddr->sin_addr), ntohs(scan->daddr->sin_port));
			scan->status = CLOSED;
			break ;
		}
		/* A socket is ready, our port is open */
		else if (select(sockfd+1, &rfds, &lfds, &efds, &timeout)) {
			if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
				fprintf(stderr, "[*] Received TCP [OPEN] response from: %s:%d\n",
					inet_ntoa(scan->daddr->sin_addr), ntohs(scan->daddr->sin_port));
			scan->status = OPEN;
			break ;
		}
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG) {
			if (i == 0)
				fprintf(stderr, "[*] TCP request to %s:%d timedout\n",
					inet_ntoa(scan->daddr->sin_addr), ntohs(scan->daddr->sin_port));
			else
				fprintf(stderr, "[*] No response from %s:%d, setting status to [FILTERED]\n",
					inet_ntoa(scan->daddr->sin_addr), ntohs(scan->daddr->sin_port));
		}
		i++;
	}

	/* Scan end time */
	if ((gettimeofday(&scan->end_time, NULL)) != 0) {
		scan->end_time.tv_sec = 0;
		scan->end_time.tv_usec = 0;
	}

	close(sockfd);
	return 0;
}
