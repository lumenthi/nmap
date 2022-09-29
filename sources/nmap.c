#include "nmap.h"
#include "options.h"

int ft_nmap(char *path)
{
	int ret;
	char *status[] = {"OPEN",
		"CLOSED", "FILTERED", "DOWN", "ERROR", "UNKNOWN"};
	struct s_ip *ips = g_data.ips;
	struct s_scan *scans;

	if (getuid() != 0) {
		fprintf(stderr, "%s: Not allowed to create raw sockets, run as root\n",
			path);
		return 1;
	}

	while (ips) {
		scans = ips->scans;
		while (scans) {
			printf("==============\n");
			ret = syn_scan(ips->destination, scans->dport);
			printf("[*] SYN scan result: %s\n", status[ret]);
			printf("==============\n");
			scans = scans->next;
		}
		ips = ips->next;
	}
	free_ips(&g_data.ips);
	return 0;
}
