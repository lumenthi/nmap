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

static int assign_payload(char *port_list, char *payload, struct port *ports)
{
	char **split;
	int i = 0;
	int port;

	split = ft_strsplit(port_list, ',');
	while (split[i]) {
		port = ft_atoi(split[i]);
		if (port <= USHRT_MAX && port >= 0) {
			if (!ports[port].payload) {
				ports[port].payload = ft_strdup(payload);
				/* printf("Port[%d] = %s\n", port, payload); */
			}
		}
		i++;
	}
	free_split(split);
	return 0;
}

static int read_payloads(int fd, struct port *ports)
{
	char *buffer;
	char **split;

	while (get_next_line(fd, &buffer) != 0) {
		split = ft_strsplit(buffer, '|');
		if (split_size(split) >= 1 && split[0] && split[1])
			assign_payload(split[0], split[1], ports);
		free_split(split);
		free(buffer);
	}
	return 0;
}

int get_payloads()
{
	int fd;

	if (!(g_data.opt & OPT_SCAN_UDP)) {
		if (g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[*] No need to parse payloads, UDP scan is not involved\n");
		return 0;
	}

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Parsing payloads database %s\n", DB_PAYLOADS);

	/* Reading process */
	fd = open(DB_PAYLOADS, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed to get payloads database, UDP scan will be affected\n");
		return 0;
	}

	read_payloads(fd, g_data.ports);

	close(fd);

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Parsed payloads database sucessfully\n");

	return 0;
}

void free_payloads(void)
{
	int i = 0;

	while (i <= USHRT_MAX) {
		if (g_data.ports) {
			if (g_data.ports[i].payload)
				free(g_data.ports[i].payload);
		}
		i++;
	}
}
