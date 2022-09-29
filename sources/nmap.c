#include "nmap.h"
#include "options.h"

int ft_nmap(char *path)
{
	struct s_ip *ip = g_data.ips;
	struct s_scan *scan;

	if (getuid() != 0) {
		fprintf(stderr, "%s: Not allowed to create raw sockets, run as root\n",
			path);
		return 1;
	}

	while (ip) {
		scan = ip->scans;
		while (scan) {
			scan->status = -1;

			/* TODO: Cast / Check return */
			scan->saddr = malloc(sizeof(struct sockaddr_in));
			scan->daddr = malloc(sizeof(struct sockaddr_in));
			/* TODO: Minimise calls to config functions */
			if (dconfig(ip->destination, scan->dport, scan->daddr, &scan->dhostname) != 0)
				scan->status = DOWN;
			if (sconfig(inet_ntoa(scan->daddr->sin_addr), scan->saddr) != 0)
				scan->status = ERROR;

			if (scan->status == -1)
				syn_scan(scan);
			scan = scan->next;
		}
		ip = ip->next;
	}

	print_scans(g_data.ips);
	free_ips(&g_data.ips);
	return 0;
}
