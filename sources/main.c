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

	long pagesize = sysconf(_SC_PAGE_SIZE);
	long a_pages = sysconf(_SC_AVPHYS_PAGES);
	uint64_t total_size = pagesize * a_pages;
	uint64_t a_memory = total_size * 0.8 - sizeof(g_data);
	g_data.max_ips = a_memory / sizeof(struct s_ip);
	/*printf("Page size = %ld\n", pagesize);
	printf("Available pages = %ld\n", a_pages);
	printf("Total size = %ld\n", total_size);
	printf("size of g_data = %ld\n", sizeof(t_data));
	printf("size of struct ip = %ld\n", sizeof(struct s_ip));
	printf("Free size = %ld\n", a_memory);
	printf("%lu max ips\n", g_data.max_ips);*/

	g_data.tmp_ips = malloc(sizeof(struct s_tmp_ip) * MAX_IPS);
	if (!g_data.tmp_ips) {
		fprintf(stderr, "Could not realloc tmp ips\n");
		free_and_exit(EXIT_FAILURE);
	}
	ft_memset(g_data.tmp_ips, 0, sizeof(struct s_tmp_ip) * MAX_IPS);

	/*printf("sizeof(s_ip) = %ld\n", sizeof(struct s_ip));
	printf("sizeof(s_port) = %ld\n", sizeof(struct s_port));
	printf("sizeof(s_scan) = %ld\n", sizeof(struct s_scan));*/
}

int		main(int argc, char **argv)
{
	/* Timers for the whole proccess */
	struct timeval start_time;
	struct timeval end_time;
	struct tm *local_time;
	time_t ctime;

	/* Timers for the scan process */
	struct timeval sstart_time;
	struct timeval send_time;

	if (argc < 2) {
		fprintf(stdout, "Use -h for help\n");
		print_usage(stdout);
		return 1;
	}

	ctime = time(NULL);
	local_time = localtime(&ctime);

	printf("Starting ft_nmap 0.1 (https://github.com/lumenthi/nmap)"\
		" at %d-%d-%d %d:%d CEST\n", 1900 + local_time->tm_year, local_time->tm_mon + 1,
		local_time->tm_mday, local_time->tm_hour, local_time->tm_min);

	/* ft_nmap start time */
	if ((gettimeofday(&start_time, NULL)) != 0) {
		start_time.tv_sec = 0;
		start_time.tv_usec = 0;
	}

	if (parse_nmap_args(argc, argv) != 0)
		free_and_exit(EXIT_FAILURE);

	if (g_data.tmp_ips == NULL) {
		fprintf(stdout, "Use -h for help\n");
		print_usage(stdout);
		free_and_exit(EXIT_FAILURE);
	}

	/* Getting service list */
	if (get_services() != 0)
		free_and_exit(EXIT_FAILURE);

	/* Getting service list */
	if (get_payloads() != 0)
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
