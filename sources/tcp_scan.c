#include "nmap.h"
#include "options.h"

int tcp_scan(struct sockaddr_in daddr,
struct s_scan *scan, struct timeval timeout)
{
	int sockfd;
	int err;
	int len = sizeof(err);
	int i = 0;

	/* Prepare ports */
	scan->saddr.sin_port = htons(scan->sport);
	daddr.sin_port = htons(scan->dport);

	/* Socket creation */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET) {
			pthread_mutex_lock(&g_data.print_lock);
			fprintf(stderr, "[%ld] Failed to create socket\n", pthread_self());
			pthread_mutex_unlock(&g_data.print_lock);
		}
		scan->status = ERROR;
		return 1;
	}

	/* Not authorized, remains a bonus */
	if (fcntl(sockfd, F_SETFL, O_NONBLOCK) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET) {
			pthread_mutex_lock(&g_data.print_lock);
			fprintf(stderr, "[%ld] Failed to set fcntl option\n", pthread_self());
			pthread_mutex_unlock(&g_data.print_lock);
		}
		scan->status = ERROR;
		close(sockfd);
		return 1;
	}

	/* Scan start time */
	if ((gettimeofday(&scan->start_time, NULL)) != 0) {
		scan->start_time.tv_sec = 0;
		scan->start_time.tv_usec = 0;
	}

	/* Service assignation */
	scan->service = g_data.ports[scan->dport].tcp_name;
	scan->service_desc = g_data.ports[scan->dport].tcp_desc;

	/* Setting write fds for select */
	fd_set wfds;
	FD_ZERO(&wfds);

	/* Default status */
	scan->status = FILTERED;
	while (i < 2) {
		/* Setting data */
		timeout.tv_sec = 1;
		timeout.tv_usec = 345678;
		FD_ZERO(&wfds);
		FD_SET(sockfd, &wfds);

		/* Verbose print */
		if (g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG) {
			pthread_mutex_lock(&g_data.print_lock);
			fprintf(stderr, "[%ld] Sent TCP request to %s:%d\n", pthread_self(),
				inet_ntoa(daddr.sin_addr), ntohs(daddr.sin_port));
			pthread_mutex_unlock(&g_data.print_lock);
		}

		/* Connect process */
		connect(sockfd, (struct sockaddr *)&daddr, sizeof(struct sockaddr));

		if (errno == ENETUNREACH) {
			if (g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG) {
				pthread_mutex_lock(&g_data.print_lock);
				fprintf(stderr, "[%ld] %s:%d is unreachable\n", pthread_self(),
					inet_ntoa(daddr.sin_addr), ntohs(daddr.sin_port));
				pthread_mutex_unlock(&g_data.print_lock);
			}
			scan->status = FILTERED;
			break;
		}

		/* SO_ERROR check */
		getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, (socklen_t *)&len);	

		/* Getsockopt analysis */
		if (err == ECONNREFUSED) {
			if (g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG) {
				pthread_mutex_lock(&g_data.print_lock);
				fprintf(stderr, "[%ld] Received TCP [CLOSED] response from %s:%d\n",
					pthread_self(), inet_ntoa(daddr.sin_addr),
					ntohs(daddr.sin_port));
				pthread_mutex_unlock(&g_data.print_lock);
			}
			scan->status = CLOSED;
			break ;
		}
		else if (err) {
			if (g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG) {
				pthread_mutex_lock(&g_data.print_lock);
				fprintf(stderr, "[%ld] Received TCP [FILTERED] response from %s:%d\n",
					pthread_self(), inet_ntoa(daddr.sin_addr),
					ntohs(daddr.sin_port));
				pthread_mutex_unlock(&g_data.print_lock);
			}
			break ;
		}
		/* A socket is ready, our port is open */
		else if (select(sockfd+1, NULL, &wfds, NULL, &timeout)) {
			if (write(sockfd, NULL, 0) != -1) {
				if (g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG) {
					pthread_mutex_lock(&g_data.print_lock);
					fprintf(stderr, "[%ld] Received TCP [OPEN] response from: %s:%d\n",
						pthread_self(), inet_ntoa(daddr.sin_addr),
						ntohs(daddr.sin_port));
					pthread_mutex_unlock(&g_data.print_lock);
				}
				scan->status = OPEN;
			}
			else
				scan->status = CLOSED;
			break ;
		}
		if (g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG) {
			pthread_mutex_lock(&g_data.print_lock);
			if (i == 0)
				fprintf(stderr, "[%ld] TCP request to %s:%d timedout\n",
					pthread_self(), inet_ntoa(daddr.sin_addr),
					ntohs(daddr.sin_port));
			else
				fprintf(stderr, "[%ld] No response from %s:%d, setting status to [FILTERED]\n",
					pthread_self(), inet_ntoa(daddr.sin_addr),
					ntohs(daddr.sin_port));
			pthread_mutex_unlock(&g_data.print_lock);
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
