#include "nmap.h"
#include "options.h"

t_data	g_data;

void	init_data(t_range *port_range)
{
	ft_bzero(&g_data, sizeof(g_data));

	/* Default ports scan */
	port_range->start = DEFAULT_START_PORT;
	port_range->end = DEFAULT_END_PORT;

	/* Check privilege level, so we adapt scanning method */
	g_data.privilegied = getuid() == 0 ? 1 : 0;

	/* Default SCAN */
	g_data.opt |= g_data.privilegied ? OPT_SCAN_SYN : OPT_SCAN_TCP;

	g_data.port_counter = 0;

	/* TODO: init default settings */
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
