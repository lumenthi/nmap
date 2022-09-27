#include "nmap.h"
#include "options.h"

t_data	g_data;

void	init_data(void)
{
	ft_bzero(&g_data, sizeof(g_data));
	/* TODO: init default settings */
	g_data.destination = NULL;
}

int		main(int argc, char **argv)
{
	if (argc < 3)
		return 1;

	init_data();
	if (parse_nmap_options(argc, argv) != 0)
		free_and_exit(EXIT_FAILURE);
	ft_nmap(g_data.destination, g_data.dest_port, argv[0]);
	free_and_exit(EXIT_SUCCESS);
	return 0;
}
