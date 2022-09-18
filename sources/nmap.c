#include "nmap.h"

static int resolve(char *host, t_data *g_data)
{
	struct addrinfo hints;

	if (!ft_memset(&hints, 0, sizeof(struct addrinfo)))
		return 1;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	/* Subject to any restrictions imposed by hints */
	if (getaddrinfo(host, NULL, &hints, &g_data->host_info) == -1 ||
		g_data->host_info == NULL)
		return 1;

	g_data->host_addr = g_data->host_info->ai_addr;
	g_data->servaddr = *(struct sockaddr_in *)g_data->host_addr;

	ft_strncpy(g_data->ipv4, inet_ntoa(g_data->servaddr.sin_addr),
		sizeof(g_data->ipv4));

	return 0;
}

int ft_nmap(char *destination, uint8_t args, char *path)
{
	(void)args;

	t_data g_data = {0};

	if (!destination) {
		fprintf(stderr, "%s: Empty hostname\n", path);
		return 1;
	}

	if (getuid() != 0) {
		fprintf(stderr, "%s: %s: Not allowed to create raw sockets, run as root\n",
			path, destination);
		return 1;
	}

	/* Resolving host */
	if (resolve(destination, &g_data)) {
		fprintf(stderr, "%s: %s: Name or service not known\n", path, destination);
		return 1;
	} /* g_data.host_info is allocated ! Must free it now */

	printf("%s: %s\n", destination, g_data.ipv4);

	freeaddrinfo(g_data.host_info);

	return 0;
}
