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

	/* TODO: init default settings */
}

/* TODO: Once finished, remove server related code in makefile/sources */
/* TODO: Check allowed functions */
int		main(int argc, char **argv)
{
	if (argc < 2)
		return 1;

	if (parse_nmap_args(argc, argv) != 0)
		free_and_exit(EXIT_FAILURE);
	ft_nmap(argv[0]);
	free_and_exit(EXIT_SUCCESS);

	return 0;
}
