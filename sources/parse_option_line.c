#include "options.h"
#include "libft.h"
#include "nmap.h"

static void	print_version(void)
{
	printf("lumenthi and lnicosia's ft_nmap version 1.0\n");
	printf("This program is free software; you may redistribute it\n");
	printf("This program has absolutely no warranty\n");
}

void		print_usage(FILE* f)
{
	fprintf(f, "Usage:\n  ft_nmap [Scan Type(s)] [Options] {target specification}\n");
	fprintf(f, "TARGET SPECIFICATION\n");
	fprintf(f, "%s%2s%-26s%s", "  ", "", "  ", "\n");
}

static int		parse_positive_range(t_set *set, char *arg, t_range *curr_range)
{
	size_t	i, j;
	int		is_range;

	i = 0;
	printf("Parsing range |%s|\n", arg);
	while (arg[i]) {
		j = i;
		is_range = 0;
		curr_range->start = 0;
		curr_range->end = 0;
		while (arg[j] && arg[j] != ',') {
			/* Each "," is a new range to parse */
			if (arg[j] == '-') {
				char *str = strdup(arg + i);
				str[j] = 0;
				printf("Current range = |%s|\n", str);
				free(str);
				if (is_range == 1) {
					fprintf(stderr, "Error #486: Your port specifications are illegal." \
							"  Exemple of proper form: \"-100,200-1024\"\nQUITTING!\n");
					return 1;
				}
				set->nb_ranges++;
				is_range = 1;
				curr_range->start = ft_atoi(arg + i);
				if (arg[j + 1])
					curr_range->end = ft_atoi(arg + j + 1);
				else
					curr_range->end = set->max;
				printf("Current range = [%d - %d]\n", curr_range->start, curr_range->end);
			}
			else {
				char *str = strdup(arg + i);
				str[j] = 0;
				printf("Current range = |%s|\n", str);
				free(str);
			}
			j++;
		}
		i++;
	}
	return 0;
}

static int get_next_scan(char *current)
{
	int len = 0;

	while (*current && *current != ',') {
		len++;
		current++;
	}

	return len;
}

static uint8_t enable_scan(char *str, int str_len)
{
	char *scans[] = {"SYN", "NULL", "FIN", "XMAS", "ACK", "UDP", "TCP", NULL};
	/* Privileges required for scans */
	uint8_t pri[] = {1,     1,      1,     1,      1,     1,     0,     0};
	int i = 0; /* Start at SYN */

	while (scans[i]) {
		if (ft_strncmp(str, scans[i], str_len) == 0) {
			/* i+2 since our first scantype starts at 1UL<<2 in options.h */
			if (g_data.privilegied < pri[i])
				return SCAN_PRIVILEGES;
			g_data.opt |= (1UL << (i+2));
			return SCAN_VALID;
		}
		i++;
	}
	return SCAN_INVALID;
}

static uint8_t parse_scans(char *optarg)
{
	char *current = optarg;
	int curr_len;
	uint8_t ret;

	g_data.opt &= g_data.privilegied ?
		~OPT_SCAN_SYN : ~OPT_SCAN_TCP;

	while ((curr_len = get_next_scan(current))) {
		/* printf("[*] Current OPT: %s with size: %d\n",
			current, curr_len); */
		ret = enable_scan(current, curr_len);
		if (ret != SCAN_VALID)
			return ret;
		current += *(current+curr_len) == ',' ?
			curr_len+1 : curr_len;
	}

	return 0;
}

static void assign_ports(uint16_t *port_min, uint16_t *port_max)
{
	int device_size = 11;
	int fd;
	char data[device_size];
	int i = 0;

	*port_min = DEFAULT_EPHEMERAL_MIN;
	*port_max = DEFAULT_EPHEMERAL_MAX;

	fd = open("/proc/sys/net/ipv4/ip_local_port_range", O_RDONLY);
	if (fd < 0)
		return;

	device_size = read(fd, data, device_size);
	*port_min = 0;
	/* Read min */
	while (ft_isdigit(data[i]) && i < device_size) {
		if (ft_isdigit(data[i]))
			*port_min = *port_min * 10 + (data[i] - '0');
		i++;
	}
	*port_max = 0;
	/* Read max */
	while (i < device_size) {
		if (ft_isdigit(data[i]))
			*port_max = *port_max * 10 + (data[i] - '0');
		i++;
	}

	/* printf("Port min: %d, Port max: %d\n", *port_min, *port_max); */

	close(fd);
}

static void add_ip(char *ip_string, t_range curr_range)
{
	struct s_ip *tmp;

	tmp = (struct s_ip *)malloc(sizeof(struct s_ip));
	if (tmp) {
		ft_memset(tmp, 0, sizeof(struct s_ip));
		tmp->destination = ip_string;
		/* Default status */
		tmp->status = UP;
		/* Prepare addr structs */
		tmp->saddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		tmp->daddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		if (!tmp->saddr || !tmp->daddr)
			tmp->status = ERROR;
		if (dconfig(tmp->destination, 0, tmp->daddr, &tmp->dhostname) != 0)
			tmp->status = DOWN;
		if (sconfig(inet_ntoa(tmp->daddr->sin_addr), tmp->saddr) != 0)
			tmp->status = ERROR;
		push_ports(&tmp, curr_range.start, curr_range.end);
		push_ip(&g_data.ips, tmp);
	}
}

/*
 **	Parse all the options
 */

int	parse_nmap_args(int ac, char **av)
{
	int	opt, option_index = 0, count = 1;
	char		*optarg = NULL;
	const char	*optstring = "-hvVp:i:f:t:s:";
	static struct option long_options[] = {
		{"help",	0,					0, 'h'},
		{"version",	0,					0, 'V'},
		{"verbose",	optional_argument,	0, 'v'},
		{"ports",	required_argument,	0, 'p'},
		{"threads",	required_argument,	0, 't'},
		{"ip",		required_argument,	0, 'i'},
		{"file",	required_argument,	0, 'f'},
		{"scan",	required_argument,	0, 's'},
		{0,			0,					0,	0 }
	};
	t_range	curr_range;

	init_data(&curr_range);

	while ((opt = ft_getopt_long(ac, av, optstring, &optarg,
					long_options, &option_index)) != -1) {
		switch (opt) {
			case 's':
				{
					int scan_ret;
					scan_ret = parse_scans(optarg);
					if (scan_ret == SCAN_INVALID) {
						fprintf(stderr, "Invalid scan type\n");
						return 1;
					}
					else if (scan_ret == SCAN_PRIVILEGES) {
						fprintf(stderr,
						"You requested a scan type which requires root privileges.\n");
						return 1;
					}
					break;
				}
			case 'v':
				/* TODO: optional argument for short options */
				g_data.opt |= OPT_VERBOSE_INFO;
				if (optarg != NULL) {
					if (ft_strcmp(optarg, "DEBUG") == 0) {
						g_data.opt |= OPT_VERBOSE_DEBUG;
						g_data.opt &= ~OPT_VERBOSE_INFO;
					}
					else if (ft_strcmp(optarg, "INFO") == 0)
						g_data.opt |= OPT_VERBOSE_INFO;
					else {
						fprintf(stderr, "Invalid verbose level\n");
						return 1;
					}
				}
				break;
			case 'i':
				{
					break;
				}
			case 't':
				{
					int threads = ft_atoi(optarg);
					if (threads < 0 || threads > 250) {
						fprintf(stderr, "Invalid thread number [0-250]\n");
						return 1;
					}
					g_data.nb_threads = threads;
					break;
				}
			case 'V':
				print_version();
				return 1;
			case 'h':
				print_usage(stdout);
				return 1;
			case 'p':
				{
					/* TODO: parse ranges of ports */
					/* t_set	set;
					ft_bzero(&set, sizeof(set));
					set.min = 1;
					set.max = MAX_PORT;
					parse_positive_range(&set, optarg, &curr_range); */
					(void)parse_positive_range;
					curr_range.start = ft_atoi(optarg);
					curr_range.end = ft_atoi(optarg);
					break;
				}
			case '?':
				{
					free_and_exit(255);
					break;
				}
			default:
				{
					free_and_exit(255);
					break;
				}
		}
		count++;
	}

	/* Get ephemeral port range for TCP source */
	assign_ports(&g_data.port_min, &g_data.port_max);
	if (g_data.port_min > g_data.port_max) {
		fprintf(stderr, "%s: Source ports configuration error\n",
			av[0]);
		return 1;
	}

	for (int i = 1; i < ac; i++) {
		if (!is_arg_an_opt(av, i, optstring, long_options)) {
			/* Pushing ip in the IP list to scan */
			add_ip(av[i], curr_range);
		}
	}
	return 0;
}
