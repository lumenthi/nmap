#include "nmap.h"

static int resolve(char *host, t_data *g_data)
{
	struct addrinfo hints;

	if (!ft_memset(&hints, 0, sizeof(struct addrinfo)))
		return 1;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

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

int syn_scan(char *destination, uint16_t port)
{
	(void)port;
	t_data g_data = {0};
	int sockfd;
	int ttl = -1;

	/* Socket creation */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		fprintf(stderr, "%s: Failed to create TCP socket\n", destination);
		return 1;
	}

	/* Resolving host */
	if (resolve(destination, &g_data)) {
		fprintf(stderr, "%s: Name or service not known\n", destination);
		return 1;
	} /* g_data.host_info is allocated ! Must free it now */

	/* Set options */
	if ((setsockopt(sockfd, SOL_IP, IP_TTL, &ttl, sizeof(ttl))) != 0) {
		fprintf(stderr, "%s: Failed to set TTL option\n", destination);
		return 1;
	}

	printf("%s: %s\n", destination, g_data.ipv4);

	g_data.servaddr.sin_family = AF_INET;
	g_data.servaddr.sin_port = htons(port);
	g_data.host_addr = (struct sockaddr *)&g_data.servaddr;

	int ret = connect(sockfd, g_data.host_addr, sizeof(g_data.servaddr));
	printf("Connect: %d\n", ret);

	freeaddrinfo(g_data.host_info);
	close(sockfd);
	return 0;
}

int ft_nmap(char *destination, uint8_t args, char *path)
{
	(void)args;

	if (!destination) {
		fprintf(stderr, "%s: Empty hostname\n", path);
		return 1;
	}

	if (getuid() != 0) {
		fprintf(stderr, "%s: %s: Not allowed to create raw sockets, run as root\n",
			path, destination);
		return 1;
	}

	syn_scan(destination, 22);

	return 0;
}
