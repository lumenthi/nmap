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
		/* Default status */
		ip->status = UP;
		/* Prepare addr structs */
		ip->saddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		ip->daddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		if (!ip->saddr || !ip->daddr)
			ip->status = ERROR;
		if (dconfig(ip->destination, 0, ip->daddr, &ip->dhostname) != 0)
			ip->status = DOWN;
		if (sconfig(inet_ntoa(ip->daddr->sin_addr), ip->saddr) != 0)
			ip->status = ERROR;

		/* Resolve scans for this IP */
		while (ip->status == UP && scan) {
			scan->status = READY;

			scan->saddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
			if (!scan->saddr)
				scan->status = ERROR;
			else {
				ft_memcpy(scan->saddr, ip->saddr, sizeof(struct sockaddr_in));
				scan->sport = ft_random(32768, 60999);
			}

			scan->daddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
			if (!scan->daddr)
				scan->status = ERROR;
			else {
				ft_memcpy(scan->daddr, ip->daddr, sizeof(struct sockaddr_in));
				scan->dhostname = ip->dhostname;
			}

			if (scan->status == READY)
				syn_scan(scan);
			scan = scan->next;
		}
		ip = ip->next;
	}

	print_scans(g_data.ips);
	free_ips(&g_data.ips);
	return 0;
}
