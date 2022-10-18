#include "services.h"
#include "nmap.h"
#include "options.h"

static void free_split(char **split)
{
	char **tmp = split;

	while (*tmp) {
		free(*tmp);
		tmp++;
	}
	free(split);
}

static size_t split_size(char **split)
{
	int i = 0;

	if (!split)
		return 0;

	while (split[i])
		i++;

	return i;
}

static int get_infos(char *str, int *port, int *protocol)
{
	char *tmp = str;
	char *split = ft_strrchr(str, '/');
	char *proto;

	if (!split || !(split+1))
		return 0;

	proto = split+1;

	*split = '\0';
	*port = ft_atoi(tmp);

	if (*port < 0 || *port > USHRT_MAX)
		return 0;

	if (!ft_strncmp(proto, "tcp", 3))
		*protocol = IPPROTO_TCP;
	else if (!ft_strncmp(proto, "udp", 3))
		*protocol = IPPROTO_UDP;
	else
		return 0;

	return 1;
}

static void get_desc(char *str, char **desc)
{
	int i = 0;

	while (str[i] == '#' || str[i] == ' ')
		i++;

	if (str[i])
		*desc = ft_strdup(str+i);
}

static int read_services(int fd, struct service *tcp, struct service *udp)
{
	char *buffer;
	char **split;
	int port;
	int protocol;

	while (get_next_line(fd, &buffer) != 0) {
		split = ft_strsplit(buffer, '\t');
		if (split_size(split) >= 3 &&
			split[0] && split[1] && split[2])
		{
			if (get_infos(split[1], &port, &protocol)) {
				/* TODO: Description ?? */
				if (protocol == IPPROTO_UDP) {
					if (!udp[port].name) {
						udp[port].name = ft_strdup(split[0]);
						if (!udp[port].desc && split[3])
							get_desc(split[3], &udp[port].desc);
					}
				}
				else if (protocol == IPPROTO_TCP) {
					if (!tcp[port].name) {
						tcp[port].name = ft_strdup(split[0]);
						if (!tcp[port].desc && split[3])
							get_desc(split[3], &tcp[port].desc);
					}
				}
			}
		}
		free_split(split);
		free(buffer);
	}
	return 0;
}

int get_services()
{
	int fd;

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Parsing services database %s\n", DB_SERVICES);

	/* Structures allocation */
	g_data.tcp_services = malloc(sizeof(struct service) * (USHRT_MAX+1));
	g_data.udp_services = malloc(sizeof(struct service) * (USHRT_MAX+1));
	if (!g_data.tcp_services || !g_data.udp_services) {
		fprintf(stderr, "Not enough memory to handle service detection\n");
		return -1;
	}
	ft_bzero(g_data.tcp_services, sizeof(struct service) * (USHRT_MAX+1));
	ft_bzero(g_data.udp_services, sizeof(struct service) * (USHRT_MAX+1));

	/* Reading process */
	fd = open(DB_SERVICES, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed to get services database, service detection will be affected\n");
		return 0;
	}

	read_services(fd, g_data.tcp_services, g_data.udp_services);

	/* Debug print */
	/* int i = 0;
	while (i <= USHRT_MAX) {
		if (g_data.tcp_services[i].name)
			printf("[*] Port %d (tcp) has service [%s] with desc [%s]\n", i,
				g_data.tcp_services[i].name, g_data.tcp_services[i].desc);
		if (g_data.udp_services[i].name)
			printf("[*] Port %d (udp) has service [%s] with desc [%s]\n", i,
				g_data.udp_services[i].name, g_data.udp_services[i].desc);
		i++;
	} */

	close(fd);

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Parsed services database sucessfully\n");

	return 0;
}

void free_services(void)
{
	int i = 0;

	while (i <= USHRT_MAX) {
		/* TCP services */
		if (g_data.tcp_services) {
			if (g_data.tcp_services[i].name)
				free(g_data.tcp_services[i].name);
			if (g_data.tcp_services[i].desc)
				free(g_data.tcp_services[i].desc);
		}

		/* UDP services */
		if (g_data.udp_services) {
			if (g_data.udp_services[i].name)
				free(g_data.udp_services[i].name);
			if (g_data.udp_services[i].desc)
				free(g_data.udp_services[i].desc);
		}
		i++;
	}

	if (g_data.tcp_services)
		free(g_data.tcp_services);
	if (g_data.udp_services)
		free(g_data.udp_services);
}
