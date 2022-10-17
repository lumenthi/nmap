#include "nmap.h"
#include "options.h"

static int run_scan(struct s_scan *scan)
{
	/* TODO: match nmap's options for each scan type (both IP and the next layer) */
	switch (scan->scantype) {
		case OPT_SCAN_SYN:
			syn_scan(scan);
			break;
		case OPT_SCAN_TCP:
			//syn_scan(scan);
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

	return 0;
}

static int launch_scan(void *rip)
{
	struct s_ip *ip = (struct s_ip *)rip;
	struct s_scan *scan;

	while (ip) {
		//printf("[*] Looking for ip: %s\n", ip->destination);
		if (ip->status == UP) {
			scan = ip->scans;

			/* Resolve scans for this IP */
			while (scan) {
				LOCK(scan);
				if (scan->status == READY) {
					/* TODO: Must lock or some scan will return filtered */
					scan->status = SCANNING;
					UNLOCK(scan);
					run_scan(scan);
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
