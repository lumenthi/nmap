#include "nmap.h"
#include "options.h"

/* Contains infos for our printing function */
struct s_pinfo {
	size_t ctotal; /* Scanned port counter */
	size_t copen; /* Open counter */
	size_t cfilter; /* Filtered counter */
	size_t cclose; /* Close counter */
	size_t cerror; /* Error counter */
	uint8_t menu; /* 0 or 1, to set if the menu bar is diplayed */
	uint8_t tick; /* Set to one when printed one occurence for a port */
};

static int scan_index(int scan_code)
{
	int count = -1;

	while (scan_code) {
		count++;
		scan_code >>= 1;
	}
	/* -2 since our first OPT flag starts at 1UL<<2 */
	return count-2;
}

static void print_content(struct s_scan *scan, struct s_pinfo *info)
{
	long int sec;
	long int usec;
	long long total_usec;

	char *status[] = {"OPEN", "CLOSED", "FILTERED", "DOWN",
		"ERROR", "UNKNOWN", "TIMEOUT", "UP", "READY", NULL};
	char *scans[] = {"SYN", "NULL", "FIN", "XMAS",
		"ACK", "UDP", NULL};

	sec = scan->end_time.tv_sec - scan->start_time.tv_sec;
	usec = scan->end_time.tv_usec - scan->start_time.tv_usec;
	total_usec = sec*1000000+usec;

	if (!(info->menu)) {
		printf("PORT   SCAN    STATE    TIME        SERVICE\n");
		info->menu = 1;
	}
	if (info->tick > 0)
		printf("|      ");
	else
		printf("%-6d ", scan->dport);

	printf("%-7s %-8s %04lld.%03lldms  %s\n",
		scans[scan_index(scan->scantype)], status[scan->status],
		total_usec/1000, total_usec %1000, scan->service);
}

static int print_ports(struct s_ip ip, uint16_t port, struct s_pinfo *info)
{
	struct s_scan *scan = ip.scans;
	int pstatus = -1; /* Final port status */

	info->tick = 0;

	while (scan) {
		if (scan->dport == port) {
			if (scan->status == OPEN || scan->status == FILTERED) {
				print_content(scan, info);
				pstatus = scan->status;
				info->tick = 1;
			}
			else {
				if (pstatus != OPEN && pstatus != FILTERED)
					pstatus = scan->status;
			}
			scan->status = PRINTED;
		}
		scan = scan->next;
	}
	return pstatus;
}

void print_scans(struct s_ip *ips)
{
	char *status[] = {"OPEN", "CLOSED", "FILTERED", "DOWN",
		"ERROR", "UNKNOWN", "TIMEOUT", "UP", "READY", NULL};

	struct s_ip *ip = ips;
	struct s_scan *scan;
	struct s_pinfo info;
	int pstatus = 0;

	while (ip) {
		ft_memset(&info, 0, sizeof(struct s_pinfo));
		printf("%s is %s\n", ip->destination, status[ip->status]);
		if (ip->status == UP) {
			scan = ip->scans;
			while (scan) {
				if (scan->status == ERROR)
					info.cerror++;
				else if (scan->status != PRINTED) {
					pstatus = print_ports(*ip, scan->dport, &info);
					if (pstatus == CLOSED)
						info.cclose++;
					else if (pstatus == OPEN)
						info.copen++;
					else if (pstatus == FILTERED)
						info.cfilter++;
					info.ctotal++;
				}
				scan = scan->next;
			}
		}
		printf("Scanned %ld port(s), %ld error(s), %ld open, %ld filtered, %ld closed\n",
			info.ctotal, info.cerror, info.copen, info.cfilter, info.cclose);
		if (ip->next)
			ft_putchar('\n');
		ip = ip->next;
	}
}
