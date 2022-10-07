#include "nmap.h"
#include "options.h"

t_data	g_data;

void	init_data()
{
	ft_bzero(&g_data, sizeof(g_data));

	/* Check privilege level, so we adapt scanning method */
	g_data.privilegied = getuid() == 0 ? 1 : 0;

	/* Default SCAN */
	g_data.opt |= g_data.privilegied ? OPT_SCAN_SYN : OPT_SCAN_TCP;

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

/* TODO: Once finished, remove server related code in makefile/sources */
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
	printf("Starting ft_nmap 0.1 ( https://github.com/lumenthi/nmap )"\
		" at [TODO:DATE] CEST\n");
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
