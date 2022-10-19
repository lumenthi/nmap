#include "nmap.h"
#include "options.h"
#include "services.h"


t_data	g_data;

void	init_data()
{
	ft_bzero(&g_data, sizeof(g_data));

	/* Check privilege level, so we adapt scanning method */
	g_data.privilegied = getuid() == 0 ? 1 : 0;

	g_data.ip_counter = 0;
	g_data.port_counter = 0;

	/* Default range */
	g_data.set.nb_ranges = 1;
	g_data.set.ranges = ft_memalloc(sizeof(t_range));
	if (!g_data.set.ranges)
		free_and_exit(EXIT_FAILURE);
	g_data.set.ranges[0].start = DEFAULT_START_PORT;
	g_data.set.ranges[0].end = DEFAULT_END_PORT;

	g_data.ipset = NULL;
}

void	print_start(void)
{
	char *scans[] = {"SYN", "NULL", "FIN", "XMAS", "ACK", "UDP", "TCP", NULL};

	printf("Starting ft_nmap 0.1 ( https://github.com/lumenthi/nmap )"\
		" at [TODO:DATE] CEST\n");

	printf("\n................. Config ..................\n");

	if (g_data.ip_counter == 1)
		printf("Target IP : %s\n", g_data.ips->dhostname);
	else {
		printf("Scanning %d targets\n", g_data.ip_counter);
	}

	printf("Number of ports to scan : %d\n",
		g_data.port_counter / g_data.ip_counter);

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
	struct timeval start_time;
	struct timeval end_time;

	if (argc < 2)
		return 1;

	/* Nmap start time */
	if ((gettimeofday(&start_time, NULL)) != 0) {
		start_time.tv_sec = 0;
		start_time.tv_usec = 0;
	}

	if (parse_nmap_args(argc, argv) != 0)
		free_and_exit(EXIT_FAILURE);

	print_start();

	/* Getting service list */
	if (get_services() != 0)
		free_and_exit(EXIT_FAILURE);

	ft_nmap(argv[0]);

	/* Nmap end time */
	if ((gettimeofday(&end_time, NULL)) != 0) {
		end_time.tv_sec = 0;
		end_time.tv_usec = 0;
	}
	print_time(start_time, end_time);

	free_and_exit(EXIT_SUCCESS);

	return 0;
}
