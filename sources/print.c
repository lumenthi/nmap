#include "nmap.h"
#include "options.h"
#include "colors.h"

/* Contains infos for our printing function */
struct s_pinfo {
	size_t copen; /* Open counter */
	size_t cfiltered; /* Filtered counter */
	size_t copen_filtered; /* open|filtered counter */
	size_t cunfiltered; /* Unfiltered counter */
	size_t cclose; /* Close counter */
	size_t cerror; /* Error counter */
	uint8_t menu; /* 0 or 1, to set if the menu bar is diplayed */
	uint8_t tick; /* Set to one when printed one occurence for a port */
};

/*
**	Print IP
*/

static void	print_ip(struct sockaddr_in *addr)
{
	char	host[128];
		ft_bzero(host, sizeof(host));
	if (getnameinfo((struct sockaddr*)addr,
		sizeof(struct sockaddr), host, sizeof(host), NULL, 0, 0))
		printf("%s ", inet_ntoa(addr->sin_addr));
	else
		printf("%s ", host);
	printf("(%s)", inet_ntoa(addr->sin_addr));
}

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

void print_time(struct timeval start_time, struct timeval end_time,
	struct timeval sstart_time, struct timeval send_time)
{
	long int diff_sec = end_time.tv_sec - start_time.tv_sec;
	long int diff_usec = end_time.tv_usec - start_time.tv_usec;
	long long total_usec = diff_sec*1000000+diff_usec;
	long long ms = total_usec % 1000000;
	long long sec = total_usec / 1000000;

	while (ms > 99)
		ms /= 10;

	/* Global timer */
	printf("\nft_nmap scanned %d ip(s) in %01lld.%02lld seconds",
		g_data.ip_counter, sec, ms);

	diff_sec = send_time.tv_sec - sstart_time.tv_sec;
	diff_usec = send_time.tv_usec - sstart_time.tv_usec;
	total_usec = diff_sec*1000000+diff_usec;
	ms = total_usec % 1000000;
	sec = total_usec / 1000000;

	while (ms > 99)
		ms /= 10;

	sec = sec < 0 ? 0 : sec;
	ms = ms < 0 ? 0 : ms;

	/* Scantime timer */
	printf(" (%01lld.%02lld seconds scantime)\n", sec, ms);
}

static void print_content(struct s_scan *scan, struct s_pinfo *info,
	const char **status, const char **colors)
{
	long int sec;
	long int usec;
	long long total_usec;
	struct servent *s_service;
	char *service = "unknown";
	char *service_desc = NULL;

	char *scans[] = {"syn", "null", "fin", "xmas",
		"ack", "udp", "tcp", NULL};

	sec = scan->end_time.tv_sec - scan->start_time.tv_sec;
	usec = scan->end_time.tv_usec - scan->start_time.tv_usec;
	total_usec = sec*1000000+usec;

	/* Service detection */
	/* Network services database file /etc/services */
	if (scan->service) {
		service = scan->service;
		service_desc = scan->service_desc;
	}
	else {
		if (scan->scantype == OPT_SCAN_UDP) {
			if ((s_service = getservbyport(scan->daddr.sin_port, "udp")))
				service = s_service->s_name;
		}
		else {
			if ((s_service = getservbyport(scan->daddr.sin_port, "tcp")))
				service = s_service->s_name;
		}
	}

	if (!(info->menu)) {
		printf("PORT   SCAN    STATE         TIME        SERVICE\n");
		info->menu = 1;
	}
	if (!info->tick)
		printf("%d\n", scan->dport);
	printf("|      ");

	const char *color;
	if (g_data.scan_types_counter == 1)
		color = colors[scan->status];
	else
		color = NMAP_COLOR_RESET;
	printf("%-7s "NMAP_COLOR_BOLD"%s%-13s"NMAP_COLOR_RESET" %04lld.%03lldms  %s",
		scans[scan_index(scan->scantype)], color, status[scan->status],
		total_usec/1000, total_usec %1000, service);

	if (g_data.opt & OPT_SERVICE_DESC && service_desc)
		printf(" (%s)", service_desc);

	printf("\n");
}

static void print_scan(struct s_scan *scan, struct s_pinfo *info,
	int *pstatus, size_t *cstatus, const char **status, const char **colors,
	struct s_port port)
{
	if (scan->status != ERROR) {
		/* TODO: Update when needed */
		if (port.final_status == OPEN
			|| g_data.port_counter / g_data.ip_counter <= 25
			|| (cstatus[FILTERED]+cstatus[OPEN_FILTERED]+cstatus[UNFILTERED]
				<= 25 && (port.final_status == FILTERED
					   || port.final_status == OPEN_FILTERED
					   || port.final_status == UNFILTERED))
			|| (cstatus[CLOSED] <= 25 && port.final_status == CLOSED))
		{
			print_content(scan, info, status, colors);
			*pstatus = port.final_status;
			info->tick = 1;
		}
		scan->status = PRINTED;
	}
}

static int print_port(struct s_port port, struct s_pinfo *info,
	const char **status, const char **colors, size_t *cstatus)
{
	int pstatus = -1; /* Final port status */

	info->tick = 0;

	if (port.syn_scan)
		print_scan(port.syn_scan, info, &pstatus, cstatus, status, colors,
			port);

	if (info->tick) {
		if (g_data.scan_types_counter > 1) {
			printf("Conclusion:    "NMAP_COLOR_BOLD"%s%s\n", colors[pstatus],
				status[pstatus]);
		}
		printf(NMAP_COLOR_RESET"+------------------------------------------\n");
	}
	return pstatus;
}

static void	count_scan_status(struct s_port *port, int ip_counter, size_t **cstatus)
{
	struct s_scan *tmp;
	int	pstatus = -1;
	struct s_scan **scans = (struct s_scan **)port;

	port->final_status = -1;

	int i = 0;
	while (i < 6) {
		if (scans[i]) {
			tmp = scans[i];
			if (pstatus == -1)
				pstatus = tmp->status;
			switch (tmp->status) {
				case OPEN:
					pstatus = OPEN;
					break;
				case FILTERED:
					if (pstatus != OPEN)
						pstatus = FILTERED;
					break;
				case UNFILTERED:
					if (pstatus == OPEN_FILTERED)
						pstatus = OPEN;
					else if (pstatus == FILTERED || pstatus == -1)
						pstatus = UNFILTERED;
					break;
				case OPEN_FILTERED:
					if (pstatus == UNFILTERED)
						pstatus = OPEN;
					if (pstatus == CLOSED || pstatus == -1)
						pstatus = OPEN_FILTERED;
					break;
				case CLOSED:
					if (pstatus == UNFILTERED || pstatus == -1)
						pstatus = CLOSED;
					break;
				default:
					pstatus = -2;
					break;
			}
		}
		i++;
	}
	port->final_status = pstatus;
	cstatus[ip_counter][pstatus]++;
}

static void	count_status(struct s_ip *ips, size_t **cstatus)
{
	struct s_ip *ip = ips;
	int ip_counter = 0;
	struct s_port *ports;
	int i = 0;

	while (ip) {
		if (ip->status == UP) {
			ports = ip->ports;
			i = 0;
			while (i < USHRT_MAX) {
				count_scan_status(&ports[i], ip_counter, cstatus);
				i++;
			}
		}
		ip = ip->next;
		ip_counter++;
	}
}

void	print_scans(struct s_ip *ips)
{
	static const char *status[] = {
		"open", "closed", "filtered", "open|filtered",
		"unfiltered", "down", "error", "unknown", "timeout", "up", "ready",
		"printed", "scanning", "invalid", "in use", "free", NULL
	};
	static const char *colors[] = {
		NMAP_COLOR_GREEN, // "open"
		NMAP_COLOR_RED, // "closed"
		NMAP_COLOR_YELLOW, // "filtered"
		NMAP_COLOR_YELLOW, // "open|filtered"
		NMAP_COLOR_YELLOW, // "unfiltered"
		NULL
	};

	size_t **cstatus;
	struct s_ip *ip = ips;
	struct s_pinfo info;
	int	ip_counter = 0;

	cstatus = malloc(sizeof(size_t*) * g_data.ip_counter);
	if (!cstatus)
		return ;
	for (int i = 0; i < g_data.ip_counter; i++) {
		cstatus[i] = malloc(sizeof(size_t) * 5);
		if (!cstatus[i])
			return ;
		ft_memset(cstatus[i], 0, sizeof(size_t) * 5);
	}

	count_status(ips, cstatus);

	while (ip) {
		ft_memset(&info, 0, sizeof(struct s_pinfo));
		if (!(g_data.opt & OPT_NO_PROGRESS)) {
			printf("\r");
			for (int_fast32_t i = 0; i < 80; i++)
				printf(" ");
			printf("\r");
			fflush(stdout);
		}
		if (ip->status == UP) {
			/* V2 */
			printf("ft_nmap scan report for ");
			print_ip(ip->daddr);
			printf("\n");
			/* TODO: Put variable at the beginning of the fonction */
			int i = 0;
			while (i < USHRT_MAX) {
				print_port(ip->ports[i], &info, status, colors, cstatus[ip_counter]);
				i++;
			}
			if (g_data.port_counter > 1)
				printf("Scanned %d ports, ", g_data.port_counter / g_data.ip_counter);
			else
				printf("Scanned %d port, ", g_data.port_counter / g_data.ip_counter);
			if (info.cerror > 1)
				printf("%ld errors", info.cerror);
			else
				printf("%ld error", info.cerror);
			for (uint8_t i = 0; i < 5; i++) {
				if (cstatus[ip_counter][i] > 0) {
					printf(", "NMAP_COLOR_BOLD"%s%lu %s",
					colors[i], cstatus[ip_counter][i], status[i]);
				}
			}
			printf(NMAP_COLOR_RESET"\n");
		}
		else
			printf("%s is %s\n", ip->destination, status[ip->status]);
		if (ip->next)
			ft_putchar('\n');
		ip = ip->next;
		ip_counter++;
	}

	if (cstatus) {
		for (int i = 0; i < g_data.ip_counter; i++) {
			if (cstatus[i])
				free(cstatus[i]);
		}
		free(cstatus);
	}
}
