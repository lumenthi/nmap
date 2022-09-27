#include "nmap.h"
#include "libft.h"

void	free_all()
{
	if (g_data.destination)
		free(g_data.destination);
}

void	free_and_exit(int exit_val)
{
	free_all();
	exit(exit_val);
}
