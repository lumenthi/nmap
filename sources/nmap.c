#include "nmap.h"
#include "options.h"

static int run_scan(struct s_scan *scan)
{
	switch (scan->scantype) {
		case OPT_SCAN_SYN:
			syn_scan(scan);
			break;
		case OPT_SCAN_TCP:
			tcp_scan(scan);
			break;
		case OPT_SCAN_FIN:
			fin_scan(scan);
			break;
		case OPT_SCAN_NULL:
			null_scan(scan);
			break;
		case OPT_SCAN_ACK:
			ack_scan(scan);
			break;
		case OPT_SCAN_XMAS:
			xmas_scan(scan);
			break;
		case OPT_SCAN_UDP:
			udp_scan(scan);
			break;
		default:
			fprintf(stderr,"Unknown scan type\n");
	}
	if (!(g_data.opt & OPT_NO_PROGRESS))
		print_progress();

	return 0;
}

static int launch_scan(void *rip)
{
	struct s_ip *ip = (struct s_ip *)rip;
	struct s_scan *scan;

	while (ip) {
		if (ip->status == UP) {
			scan = ip->scans;
			/* Resolve scans for this IP */
			while (scan) {
				if (scan->sport == g_data.port_max)
					while (g_data.ports[scan->sport].status == IN_USE);
				LOCK(scan);
				if (scan->status == READY) {
					scan->status = SCANNING;
					g_data.ports[scan->sport].status = IN_USE;
					UNLOCK(scan);
					run_scan(scan);
					g_data.ports[scan->sport].status = FREE;
				}
				else
					UNLOCK(scan);
				scan = scan->next;
			}
		}
		ip = ip->next;
	}
	return 0;
}

static int launch_threads()
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
	if (g_data.nb_threads && launch_threads() != 0) {
		fprintf(stderr, "%s: Failed to create threads\n", path);
		return 1;
	}
	else
		launch_scan(g_data.ips);

	print_scans(g_data.ips);
	return 0;
}
