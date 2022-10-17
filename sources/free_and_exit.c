#include "nmap.h"
#include "libft.h"

void free_threads()
{
	void *retval;
	int i = 0;

	if (g_data.threads) {
		while (i < g_data.created_threads)
			pthread_join(g_data.threads[i++], &retval);
		free(g_data.threads);
	}
}

void	free_all()
{
	free_threads();
	free_ips(&g_data.ips);
	if (g_data.set.ranges)
		free(g_data.set.ranges);
	if (g_data.set.single_values)
		free(g_data.set.single_values);
	if (g_data.ipset)
		free_ipset(&g_data.ipset);
	if (g_data.tcp_services)
		free(g_data.tcp_services);
	if (g_data.udp_services)
		free(g_data.udp_services);
}

void	free_and_exit(int exit_val)
{
	free_all();
	exit(exit_val);
}
