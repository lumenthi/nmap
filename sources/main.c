#include "nmap.h"
#include "options.h"

t_data	g_data;

void	init_data()
{
	ft_bzero(&g_data, sizeof(g_data));

	/* Default SCAN */
	g_data.opt |= OPT_SCAN_SYN;

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
	// ft_nmap(g_data.destination, g_data.dest_port, argv[0]);
	free_and_exit(EXIT_SUCCESS);

	return 0;
}
