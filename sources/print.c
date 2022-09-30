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
	size_t ctotal;
	size_t cclose; /* Close counter */
	size_t cerror; /* Error counter */
	uint8_t menu; /* 0 or 1, to set if the menu bar is diplayed */

	while (ip) {
		ctotal = 0;
		cclose = 0;
		cerror = 0;
		menu = 0;
		printf("%s is %s\n", ip->destination, status[ip->status]);
		if (ip->status == UP) {
			scan = ip->scans;
			while (scan) {
				if (scan->status == CLOSED)
					cclose++;
				else if (scan->status == ERROR)
					cerror++;
				else {
					if (!menu) {
						printf("PORT   STATE       TIME       SERVICE\n");
						menu = 1;
					}
					sec = scan->end_time.tv_sec - scan->start_time.tv_sec;
					usec = scan->end_time.tv_usec - scan->start_time.tv_usec;
					total_usec = sec*1000000+usec;
					printf("% 4d   %s % 4lld.%03lldms    %s\n",
						scan->dport, status[scan->status],
						total_usec/1000, total_usec %1000, scan->service);
				}
				ctotal++;
				scan = scan->next;
			}
		}
		printf("Scanned %ld port(s), %ld error(s), %ld closed\n",
			ctotal, cerror, cclose);
		if (ip->next)
			ft_putchar('\n');
		ip = ip->next;
	}
}
