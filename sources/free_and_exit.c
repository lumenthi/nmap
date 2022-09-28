#include "nmap.h"
#include "libft.h"

void	free_all()
{
	free_ips(&g_data.ips);
}

void	free_and_exit(int exit_val)
{
	free_all();
	exit(exit_val);
}
