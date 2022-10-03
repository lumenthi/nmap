#include "nmap.h"
#include "options.h"

int run_scan(struct s_scan *scan)
{
	/* printf("[*] Scanning: %d\n", scan->dport); */
	/* syn_scan(scan); */
	if (scan->scantype == OPT_SCAN_SYN)
		syn_scan(scan);
	else {
		printf("[*] Scan %d not implemented yet\n", scan->scantype);
		scan->status = ERROR;
	}

	return 0;
}

int launch_scan(void *rip)
{
	struct s_ip *ip = (struct s_ip *)rip;
	struct s_scan *scan;

	while (ip) {
		//printf("[*] Looking for ip: %s\n", ip->destination);
		scan = ip->scans;

		/* Resolve scans for this IP */
		while (scan && ip->status == UP) {
			if (scan->status == READY) {
				scan->status = SCANNING;
				run_scan(scan);
			}
			scan = scan->next;
		}
		ip = ip->next;
	}
	return 0;
}

int init_threads()
{
	void *retval;

	g_data.threads = malloc(sizeof(pthread_t) * g_data.nb_threads);
	if (!g_data.threads)
		return -1;
	ft_bzero(g_data.threads, sizeof(pthread_t) * g_data.nb_threads);

	while (g_data.created_threads < g_data.nb_threads) {
		if (pthread_create(&g_data.threads[g_data.created_threads], NULL,
			(void*)launch_scan, (void*)g_data.ips) != 0)
			return -1;
		g_data.created_threads++;
	}

	while (g_data.created_threads > 0) {
		g_data.created_threads--;
		if (pthread_join(g_data.threads[g_data.created_threads], &retval) != 0)
			return -1;
	}
	return 0;
}

int ft_nmap(char *path)
{
	if (getuid() != 0) {
		fprintf(stderr, "%s: Not allowed to create raw sockets, run as root\n",
			path);
		return 1;
	}

	if (g_data.nb_threads && init_threads() != 0) {
		fprintf(stderr, "%s: Failed to create threads\n", path);
		return 1;
	}
	else
		launch_scan(g_data.ips);

	print_scans(g_data.ips);
	return 0;
}
