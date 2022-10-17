#include "services.h"
#include "nmap.h"

int get_services()
{
	printf("[*] Services path: %s\n", DB_SERVICES);

	int fd;

	/* Structures allocation */
	g_data.tcp_services = malloc(sizeof(struct service) * USHRT_MAX);
	g_data.udp_services = malloc(sizeof(struct service) * USHRT_MAX);
	if (!g_data.tcp_services || !g_data.udp_services) {
		fprintf(stderr, "Not enough memory to handle service detection\n");
		return -1;
	}
	ft_bzero(g_data.tcp_services, sizeof(struct service) * USHRT_MAX);
	ft_bzero(g_data.udp_services, sizeof(struct service) * USHRT_MAX);

	/* Reading process */
	fd = open(DB_SERVICES, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed to get services database, service detection will be affected\n");
		return 0;
	}

	/* Debug print */
	int i = 0;
	while (i < USHRT_MAX) {
		if (g_data.tcp_services[i].name)
			printf("Port %d has service: %s\n", i, g_data.tcp_services[i].name);
		i++;
	}

	return 0;
}
