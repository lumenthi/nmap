#include "nmap.h"
#include "options.h"

static int run_scan(struct s_scan *scan, struct s_port *ports)
{
	/* TODO: match nmap's options for each scan type (both IP and the next layer) */
	switch (scan->scantype) {
		case OPT_SCAN_SYN:
			syn_scan(scan, ports);
			break;
		case OPT_SCAN_TCP:
			tcp_scan(scan);
			break;
		case OPT_SCAN_FIN:
			fin_scan(scan, ports);
			break;
		case OPT_SCAN_NULL:
			null_scan(scan, ports);
			break;
		case OPT_SCAN_ACK:
			ack_scan(scan, ports);
			break;
		case OPT_SCAN_XMAS:
			xmas_scan(scan, ports);
			break;
		case OPT_SCAN_UDP:
			udp_scan(scan, ports);
			break;
		default:
			fprintf(stderr,"Unknown scan type\n");
	}
	if (!(g_data.opt & OPT_NO_PROGRESS))
		print_progress();

	return 0;
}

static void start_scan(struct s_scan *scan, struct s_port *ports)
{
	if (scan->sport == g_data.port_max)
		while (g_data.ports[scan->sport].status == IN_USE);
	LOCK(scan);
	if (scan->status == READY) {
		scan->status = SCANNING;
		g_data.ports[scan->sport].status = IN_USE;
		UNLOCK(scan);
		run_scan(scan, ports);
		g_data.ports[scan->sport].status = FREE;
	}
	else
		UNLOCK(scan);
}

static int launch_scan(void *rip)
{
	struct s_ip *ip = (struct s_ip *)rip;
	struct s_port port;
	int i;

	while (ip) {
		if (ip->status == UP) {
			i = 0;
			while (i < USHRT_MAX+1) {
				port = ip->ports[i];
				if (port.syn_scan)
					start_scan(port.syn_scan, ip->ports);
				if (port.null_scan)
					start_scan(port.null_scan, ip->ports);
				if (port.fin_scan)
					start_scan(port.fin_scan, ip->ports);
				if (port.xmas_scan)
					start_scan(port.xmas_scan, ip->ports);
				if (port.ack_scan)
					start_scan(port.ack_scan, ip->ports);
				if (port.udp_scan)
					start_scan(port.udp_scan, ip->ports);
				if (port.tcp_scan)
					start_scan(port.tcp_scan, ip->ports);
				i++;
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

int ft_nmap(char *path, struct timeval *start, struct timeval *end)
{
	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Started scan process\n");

	start->tv_sec = 0;
	start->tv_usec = 0;
	end->tv_sec = 0;
	end->tv_usec = 0;

	/* scan process start time */
	gettimeofday(start, NULL);

	if (g_data.nb_threads && launch_threads() != 0) {
		fprintf(stderr, "%s: Failed to create threads\n", path);
		return 1;
	}
	else
		launch_scan(g_data.ips);

	/* scan process end time */
	gettimeofday(end, NULL);

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Finished scan process\n");

	print_scans(g_data.ips);
	return 0;
}
