#include "nmap.h"

void print_time(struct timeval start_time, struct timeval end_time)
{
	long int sec = end_time.tv_sec - start_time.tv_sec;
	long int usec = end_time.tv_usec - start_time.tv_usec;
	long long total_usec = sec*1000000+usec;

	printf("[*] Scan time: %lld.%03lld ms\n",
		total_usec/1000, total_usec%1000);
}

void print_scans(struct s_ip *ips)
{
	char *status[] = {"OPEN    ",
		"CLOSED  ", "FILTERED", "DOWN    ", "ERROR   ", "UNKNOWN "};
	struct s_ip *ip = ips;
	struct s_scan *scan;
	long int sec;
	long int usec;
	long long total_usec;

	while (ip) {
		/* TODO: Check if up LOL (status) */
		printf("%s is up\n", ip->destination);
		printf("PORT   STATE       TIME       SERVICE\n");
		scan = ip->scans;
		while (scan) {
			sec = scan->end_time.tv_sec - scan->start_time.tv_sec;
			usec = scan->end_time.tv_usec - scan->start_time.tv_usec;
			total_usec = sec*1000000+usec;
			/* TODO: Check division by 0 */
			printf("% 4d   %s % 4lld.%03lldms    %s\n",
				scan->dport, status[scan->status],
				total_usec/1000, total_usec %1000, scan->service);
			scan = scan->next;
		}
		ip = ip->next;
	}
}
