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
	free_payloads();
	free_services();
	free_ips(&g_data.ips);
	if (g_data.set.ranges)
		free(g_data.set.ranges);
	if (g_data.set.single_values)
		free(g_data.set.single_values);
	if (g_data.ipset)
		free_ipset(&g_data.ipset);
	if (g_data.down_ips)
		free(g_data.down_ips);
}

void	free_and_exit(int exit_val)
{
	free_all();
	if (exit_val == EXIT_FAILURE)
		fprintf(stderr, "QUITTING!\n");
	exit(exit_val);
}
