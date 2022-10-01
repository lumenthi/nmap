#include "nmap.h"
#include "options.h"

int scan_index(int scan_code)
{
	int count = -1;

	while (scan_code) {
		count++;
		scan_code >>= 1;
	}
	/* -2 since our first OPT flag starts at 1UL<<2 */
	return count-2;
}

void print_scans(struct s_ip *ips)
{
	char *status[] = {"OPEN", "CLOSED", "FILTERED", "DOWN",
		"ERROR", "UNKNOWN", "TIMEOUT", "UP", "READY", NULL};
	char *scans[] = {"SYN", "NULL", "FIN", "XMAS",
		"ACK", "UDP", NULL};

	struct s_ip *ip = ips;
	struct s_scan *scan;
	long int sec;
	long int usec;
	long long total_usec;
	size_t ctotal;
	size_t copen; /* Open counter */
	size_t cfilter; /* Filtered counter */
	size_t cclose; /* Close counter */
	size_t cerror; /* Error counter */
	uint8_t menu; /* 0 or 1, to set if the menu bar is diplayed */

	while (ip) {
		ctotal = 0;
		cfilter = 0;
		cclose = 0;
		cerror = 0;
		copen = 0;
		menu = 0;
		printf("%s is %s\n", ip->destination, status[ip->status]);
		if (ip->status == UP) {
			scan = ip->scans;
			while (scan) {
				if (scan->status == CLOSED)
					cclose++;
				else if (scan->status == ERROR)
					cerror++;
				else if (scan->status == OPEN || scan->status == FILTERED) {
					if (!menu) {
						printf("PORT   SCAN    STATE    TIME        SERVICE\n");
						menu = 1;
					}
					sec = scan->end_time.tv_sec - scan->start_time.tv_sec;
					usec = scan->end_time.tv_usec - scan->start_time.tv_usec;
					total_usec = sec*1000000+usec;
					printf("%-6d %-7s %-8s %04lld.%03lldms  %s\n",
						scan->dport, scans[scan_index(scan->scantype)],
						status[scan->status], total_usec/1000,
						total_usec %1000, scan->service);
					if (scan->status == OPEN)
						copen++;
					else if (scan->status == FILTERED)
						cfilter++;
				}
				else
					ctotal--;
				ctotal++;
				scan = scan->next;
			}
		}
		printf("Scanned %ld port(s), %ld error(s), %ld open, %ld filtered, %ld closed\n",
			ctotal, cerror, copen, cfilter, cclose);
		if (ip->next)
			ft_putchar('\n');
		ip = ip->next;
	}
}
