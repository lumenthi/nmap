#include "nmap.h"
#include "options.h"

t_data	g_data;

void	init_data()
{
	ft_bzero(&g_data, sizeof(g_data));

	/* Check privilege level, so we adapt scanning method */
	g_data.privilegied = getuid() == 0 ? 1 : 0;

	g_data.ip_counter = 0;
	g_data.vip_counter = 0;
	g_data.port_counter = 0;

	/* Default range */
	g_data.set.nb_ranges = 1;
	g_data.set.ranges = ft_memalloc(sizeof(t_range));
	if (!g_data.set.ranges)
		free_and_exit(EXIT_FAILURE);
	g_data.set.ranges[0].start = DEFAULT_START_PORT;
	g_data.set.ranges[0].end = DEFAULT_END_PORT;
	g_data.set.min = DEFAULT_START_PORT;
	g_data.set.max = DEFAULT_END_PORT;

	if (pthread_mutex_init(&g_data.print_lock, NULL) != 0) {
		perror("pthread_mutex_init");
		free_and_exit(EXIT_FAILURE);
	}

	g_data.ipset = NULL;
}

void	print_start(void)
{
	char *scans[] = {"SYN", "NULL", "FIN", "XMAS", "ACK", "UDP", "TCP", NULL};

	printf("\nStarting ft_nmap 1.0 ( https://github.com/lumenthi/nmap )"\
		" at [TODO:DATE] CEST\n");

	printf("\n................. Config ..................\n");

	if (g_data.ip_counter == 1) {
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
	g_data.total_scan_counter = g_data.port_counter * g_data.scan_types_counter;
	printf("Total scans to performed : %d\n", g_data.total_scan_counter);
	printf("Number of threads : %hhu\n", g_data.nb_threads);
	printf("...........................................\n\n");
}

/* TODO: Check allowed functions */
int		main(int argc, char **argv)
{
	/* Timers for the whole proccess */
	struct timeval start_time;
	struct timeval end_time;

	/* Timers for the scan process */
	struct timeval sstart_time;
	struct timeval send_time;

	if (argc < 2) {
		fprintf(stdout, "Use -h for help\n");
		print_usage(stdout);
		return 1;
	}

	/* ft_nmap start time */
	if ((gettimeofday(&start_time, NULL)) != 0) {
		start_time.tv_sec = 0;
		start_time.tv_usec = 0;
	}

	if (parse_nmap_args(argc, argv) != 0)
		free_and_exit(EXIT_FAILURE);

	if (g_data.ips == NULL) {
		fprintf(stdout, "Use -h for help\n");
		print_usage(stdout);
		free_and_exit(EXIT_FAILURE);
	}

	print_start();

	/* Getting service list */
	if (get_services() != 0)
		free_and_exit(EXIT_FAILURE);

	ft_nmap(argv[0], &sstart_time, &send_time);

	/* ft_nmap end time */
	if ((gettimeofday(&end_time, NULL)) != 0) {
		end_time.tv_sec = 0;
		end_time.tv_usec = 0;
	}
	print_time(start_time, end_time,
		sstart_time, send_time);

	free_and_exit(EXIT_SUCCESS);

	return 0;
}
