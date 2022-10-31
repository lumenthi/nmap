#include "nmap.h"
#include "options.h"

#define HEX_BASE_STR "0123456789ABCDEF"

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

size_t	asciilen(char *tmp, char escapes[])
{
	size_t	len = 0;

	while (*tmp) {
		// Escape codes
		if (*tmp == '\\') {
			// Hexa
			if (*(tmp + 1) == 'x') {
				if (!(*(tmp + 2))) {
					/*printf("ERROR unfinished hexa\n");*/
					return 0;
				}
				tmp += 3;
				if (*tmp != 0 && *tmp != '\\')
					tmp++;
			}
			// Standard escaped characters
			else {
				char c = escapes[(int)*(tmp + 1)];
				if (c == '?') {
					/*printf("ERROR unknown escape sequence \\%c\n",
							*(tmp + 1));*/
					return 0;
				}
				tmp += 2;
			}
		}
		else {
			tmp++;
		}
		len++;
	}
	return len;
}

static int assign_payload(char *port_list, char *payload, char escapes[], struct port *ports)
{
	char **split;
	int i = 0;
	int port;

	split = ft_strsplit(port_list, ',');
	while (split[i]) {
		port = ft_atoi(split[i]);
		if (port <= USHRT_MAX && port >= 0) {
			if (!ports[port].payload) {
				char *tmp = payload;
				ports[port].payload_len = asciilen(payload, escapes);
				if (ports[port].payload_len > 0)
					ports[port].payload = ft_strnew(ports[port].payload_len);
				if (!ports[port].payload) {
					/*fprintf(stderr, "Strnew fail!\n");*/
					free_split(split);
					return 1;
				}
				size_t j = 0;
				while (*tmp) {
					// Escape codes
					if (*tmp == '\\') {
						// Hexa
						if (*(tmp + 1) == 'x') {
							if (!(*(tmp + 2))) {
								/*fprintf(stderr, "ERROR unfinished hexa\n");*/
							}
							ports[port].payload[j] = ft_atoi_base(tmp + 2,
								HEX_BASE_STR);
							tmp += 3;
							if (*tmp != 0 && *tmp != '\\')
								tmp++;
						}
						// Standard escaped characters
						else {
							char c = escapes[(int)*(tmp + 1)];
							if (c == '?') {
								/*fprintf(stderr,
								"ERROR unknown escape sequence \\%c\n", *(tmp + 1));*/
							}
							ports[port].payload[j] = c;
							tmp += 2;
						}
					}
					else {
						ports[port].payload[j] = *tmp;
						tmp++;
					}
					j++;
				}
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
	char escapes[128];

	for (int i = 0; i < 128; i++)
		escapes[i] = '?';
	escapes['0'] = '\0';
	escapes['a'] = '\a';
	escapes['b'] = '\b';
	escapes['t'] = '\t';
	escapes['n'] = '\n';
	escapes['v'] = '\v';
	escapes['f'] = '\f';
	escapes['r'] = '\r';
	escapes['\\'] = '\\';
	escapes['\''] = '\'';
	escapes['\"'] = '\"';
	while (get_next_line(fd, &buffer) != 0) {
		split = ft_strsplit(buffer, '|');
		if (split_size(split) >= 1 && split[0] && split[1])
			assign_payload(split[0], split[1], escapes, ports);
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
