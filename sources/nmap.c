#include "nmap.h"
#include "options.h"

static void erase_progress_bar()
{
	/* Erase progress bar */
	if (!(g_data.opt & OPT_NO_PROGRESS)) {
		printf("\r");
		for (int_fast32_t i = 0; i < 80; i++)
			printf(" ");
		printf("\r");
		fflush(stdout);
	}
}

static int run_scan(struct sockaddr_in daddr,
struct s_scan *scan, struct s_port *ports, struct timeval timeout)
{
	switch (scan->scantype) {
		case OPT_SCAN_SYN:
			syn_scan(daddr, scan, ports, timeout);
			break;
		case OPT_SCAN_TCP:
			tcp_scan(daddr, scan, timeout);
			break;
		case OPT_SCAN_FIN:
			fin_scan(daddr, scan, ports, timeout);
			break;
		case OPT_SCAN_NULL:
			null_scan(daddr, scan, ports, timeout);
			break;
		case OPT_SCAN_ACK:
			ack_scan(daddr, scan, ports, timeout);
			break;
		case OPT_SCAN_XMAS:
			xmas_scan(daddr, scan, ports, timeout);
			break;
		case OPT_SCAN_UDP:
			udp_scan(daddr, scan, ports, timeout);
			break;
		default:
			fprintf(stderr,"Unknown scan type\n");
	}
	if (!(g_data.opt & OPT_NO_PROGRESS))
		print_progress();

	return 0;
}

static void start_scan(struct sockaddr_in daddr,
struct s_scan *scan, struct s_port *ports, struct timeval timeout)
{
	static uint64_t	last_probe = 0;

	if (g_data.opt & OPT_DELAY) {
		uint64_t currtime = get_time();
		while (currtime - last_probe < g_data.delay)
			currtime = get_time();
	}
	if (scan->sport == g_data.port_max)
		while (g_data.ports[scan->sport].status == IN_USE);
	LOCK(scan);
	if (scan->status == READY) {
		scan->status = SCANNING;
		g_data.ports[scan->sport].status = IN_USE;
		UNLOCK(scan);
		if (g_data.opt & OPT_DELAY)
			last_probe = get_time();
		run_scan(daddr, scan, ports, timeout);
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
		if (ip->status == UP || ip->status == SCANNING) {
			i = 0;
			while (i < USHRT_MAX+1) {
				port = ip->ports[i];
				struct sockaddr_in daddr = ip->daddr;
				daddr.sin_port = htons(i);
				if (port.syn_scan)
					start_scan(daddr, port.syn_scan, ip->ports, ip->timeout);
				if (port.null_scan)
					start_scan(daddr, port.null_scan, ip->ports, ip->timeout);
				if (port.fin_scan)
					start_scan(daddr, port.fin_scan, ip->ports, ip->timeout);
				if (port.xmas_scan)
					start_scan(daddr, port.xmas_scan, ip->ports, ip->timeout);
				if (port.ack_scan)
					start_scan(daddr, port.ack_scan, ip->ports, ip->timeout);
				if (port.udp_scan)
					start_scan(daddr, port.udp_scan, ip->ports, ip->timeout);
				if (port.tcp_scan)
					start_scan(daddr, port.tcp_scan, ip->ports, ip->timeout);
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

	if (g_data.threads)
		free(g_data.threads);
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

static void	print_start(void)
{
	char *scans[] = {"SYN", "NULL", "FIN", "XMAS", "ACK", "UDP", "TCP", NULL};

	printf("\n................. Config ..................\n");

	if (g_data.vip_counter == 1) {
		printf("Target IP : %s\n",
		g_data.ips->dhostname ? g_data.ips->dhostname : g_data.ips->destination);
	}
	else {
		printf("Scanning %d targets\n", g_data.ip_counter);
	}

	int nb_ports = g_data.vip_counter > 0 ? g_data.port_counter / g_data.vip_counter : 0;
	printf("Number of ports to scan : %d\n", nb_ports);

	printf("Scan types to be performed : ");
	int i = 0;
	char *pipe = "";
	while (scans[i])
	{
		if (g_data.opt & (1UL << (i + 2))) {
			printf("%s%s", pipe, scans[i]);
			pipe = "|";
		}
		i++;
	}
	printf("\n");
	printf("Total scans to performed : %d\n", g_data.total_scan_counter);
	printf("Number of threads : %hhu\n", g_data.nb_threads);
	printf("...........................................\n\n");
}

int ft_nmap(char *path, struct timeval *start, struct timeval *end)
{
	start->tv_sec = 0;
	start->tv_usec = 0;
	end->tv_sec = 0;
	end->tv_usec = 0;

	/* host discovery */
	if (!(g_data.opt & OPT_NO_DISCOVERY) && g_data.privilegied == 1) {
		host_discovery();
	}
	else
		g_data.vip_counter = g_data.ip_counter - g_data.nb_invalid_ips;
	
	if (g_data.vip_counter > g_data.max_ips) {
		fprintf(stderr, "Too much ips: %d (maximum %ld with your currently"
			" available memory)\n", g_data.vip_counter, g_data.max_ips);
		return 1;
	}

	if (g_data.nb_invalid_ips > 0) {
		g_data.invalid_ips = malloc(sizeof(char *) * (g_data.nb_invalid_ips+1));
		if (!g_data.invalid_ips) {
			perror("invalid ips:");
			return 1;
		}
		ft_bzero(g_data.invalid_ips, sizeof(char *) * (g_data.nb_invalid_ips+1));
	}
	if (g_data.nb_down_ips > 0) {
		g_data.down_ips = malloc(sizeof(struct in_addr) * (g_data.nb_down_ips+1));
		if (!g_data.down_ips) {
			perror("down ips:");
			return 1;
		}
		ft_bzero(g_data.down_ips, sizeof(struct in_addr) * (g_data.nb_down_ips+1));
	}

	/* Create real IPS */
	int i = 0, j = 0;
	unsigned int k = 0;
	struct s_tmp_ip *tmp = g_data.tmp_ips;
	while (k < g_data.nb_tmp_ips) {
		if (g_data.tmp_ips[k].status == UP ||
			(g_data.tmp_ips[k].status == READY && g_data.opt & OPT_NO_DISCOVERY))
			add_ip(&g_data.tmp_ips[k], &g_data.set);
		else if (tmp->status == DOWN) {
			g_data.down_ips[i] = g_data.tmp_ips[k].daddr.sin_addr;
			i++;
		}
		else {
			g_data.invalid_ips[j] = g_data.tmp_ips[k].destination;
			j++;
		}
		k++;
	}
	//print_ip_list(g_data.ips);
	free_tmp_ips(&g_data.tmp_ips);

	g_data.total_scan_counter = g_data.port_counter * g_data.scan_types_counter;

	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
		|| g_data.opt & OPT_VERBOSE_PACKET)
		print_start();

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Starting scan process\n");

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

	erase_progress_bar();

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Finished scan process\n");

	print_scans(g_data.ips);
	return 0;
}
