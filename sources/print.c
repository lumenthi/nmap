#include "nmap.h"

void print_scans(struct s_ip *ips)
{
	char *status[] = {"OPEN    ",
		"CLOSED  ", "FILTERED", "DOWN", "ERROR", "UNKNOWN ", "TIMEOUT",
		"UP", "READY"};
	struct s_ip *ip = ips;
	struct s_scan *scan;
	long int sec;
	long int usec;
	long long total_usec;

	while (ip) {
		printf("%s is %s\n", ip->destination, status[ip->status]);
		if (ip->status == UP) {
			printf("PORT   STATE       TIME       SERVICE\n");
			scan = ip->scans;
			while (scan) {
				sec = scan->end_time.tv_sec - scan->start_time.tv_sec;
				usec = scan->end_time.tv_usec - scan->start_time.tv_usec;
				total_usec = sec*1000000+usec;
				printf("% 4d   %s % 4lld.%03lldms    %s\n",
					scan->dport, status[scan->status],
					total_usec/1000, total_usec %1000, scan->service);
				scan = scan->next;
			}
		}
		ip = ip->next;
	}
}
