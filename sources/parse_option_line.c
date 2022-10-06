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

/* TODO: Infinite loop for `sudo ./ft_nmap -p --2 localhost` */
static int		parse_positive_range(t_set *set, char *arg)
{
	size_t	i, j;
	int		is_range;

	i = 0;
	while (arg[i]) {
		j = i;
		is_range = 0;
		while (arg[j]) {
			//printf("arg[j] = %c(%d)\n", arg[j], arg[j]);
			/* Each "," is a new range to parse */
			if (arg[j] == '-') {
				if (is_range == 1) {
					/*fprintf(stderr, "Error #486: Your port specifications are illegal." \
							"  Exemple of proper form: \"-100,200-1024\"\nQUITTING!\n");
					return 1;*/
				}
				is_range = 1;
				set->nb_ranges++;
				j++;
				while ((arg[j] >= '0' && arg[j] <= '9') || arg[j] == ',') {
					if (arg[j] == ',') {
						j++;
						break;
					}
					j++;
				}
				i = j;
				if (!arg[j])
					return 0;
				continue;
			}
			else if (arg[j] == ',' || !arg[j + 1]) {
				set->nb_single_values++;
				if (arg[++j])
					i = j;
				if (!arg[j])
					return 0;
				continue;
			}
			j++;
		}
		i++;
	}
	return 0;
}

int			set_positive_range(t_set *set, char *arg)
{
	size_t	i, j, crange, csingle;
	int		is_range;

	crange = 0;
	csingle = 0;
	/*printf("Parsing range |%s|\n", arg);
	printf("%ld ranges\n", set->nb_ranges);
	printf("%ld single values\n", set->nb_single_values);*/
	/* TODO: free set */
	/* TODO: remove commented prints  */
	/* TODO: remove commented prints of libft/is_arg_an_opt */
	/* TODO: Error if multiple -p */
	/* TODO: handle errors (ex: only accept digits and ',' '-' */
	set->ranges = ft_memalloc(sizeof(t_range) * set->nb_ranges);
	if (!set->ranges) {
		perror("ft_nmap: ranges alloc");
		return -1;
	}
	set->single_values = ft_memalloc(sizeof(int) * set->nb_single_values);
	if (!set->single_values) {
		set->nb_single_values = 0;
		perror("ft_nmap: single values alloc");
		return -1;
	}
	i = 0;
	while (arg[i]) {
		j = i;
		is_range = 0;
		while (arg[j]) {
			//printf("arg[j] = %c(%d)\n", arg[j], arg[j]);
			/* Each "," is a new range to parse */
			if (arg[j] == '-') {
				/*char *str = strdup(arg + i);
				str[j] = 0;
				printf("Current range str = |%s|\n", str);
				free(str);*/
				if (is_range == 1) {
					/*fprintf(stderr, "Error #486: Your port specifications are illegal." \
							"  Exemple of proper form: \"-100,200-1024\"\nQUITTING!\n");
					return 1;*/
				}
				is_range = 1;
				set->ranges[crange].start = ft_atoi(arg + i);
				if (arg[j + 1])
					set->ranges[crange].end = ft_atoi(arg + j + 1);
				else
					set->ranges[crange].end = set->max;
				/*printf("Current range = [%d - %d]\n",
					set->ranges[crange].start,
					set->ranges[crange].end);*/
				crange++;
				j++;
				/* Skip digits and ',' */
				while ((arg[j] >= '0' && arg[j] <= '9') || arg[j] == ',') {
					if (arg[j] == ',') {
						j++;
						break;
					}
					j++;
				}
				i = j;
				//printf("Remaining string = |%s|\n", arg + i);
				if (!arg[j])
					return 0;
				continue;
			}
			else if (arg[j] == ',' || !arg[j + 1]) {
				/*char *str = strdup(arg + i);
				if (!arg[j + 1])
					str[j - i + 1] = 0;
				else
					str[j - i] = 0;
				printf("Current port = |%s|\n", str);
				free(str);*/
				set->single_values[csingle++] = ft_atoi(arg + i);
				if (arg[++j])
					i = j;
				if (!arg[j])
					return 0;
				continue;
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

static void add_ip(char *ip_string, t_set *set)
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
		push_ports(&tmp, set);
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
	const char	*optstring = "hv::Vp:i:f:t:s:";
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

	init_data();

	/* Get ephemeral port range for TCP source */
	assign_ports(&g_data.port_min, &g_data.port_max);
	if (g_data.port_min > g_data.port_max) {
		fprintf(stderr, "%s: Source ports configuration error\n",
			av[0]);
		return 1;
	}

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
					if (g_data.set.ranges)
						free(g_data.set.ranges);
					if (g_data.set.single_values)
						free(g_data.set.single_values);
					ft_bzero(&g_data.set, sizeof(g_data.set));
					parse_positive_range(&g_data.set, optarg);
					if (set_positive_range(&g_data.set, optarg))
						return -1;
					/*for (size_t k = 0; k < g_data.set.nb_ranges; k++)
						printf("Range %ld: [%d - %d]\n", k + 1,
							g_data.set.ranges[k].start, g_data.set.ranges[k].end);
					for (size_t k = 0; k < g_data.set.nb_single_values; k++)
						printf("Value %ld = %d\n", k + 1,
							g_data.set.single_values[k]);*/
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

	for (int i = 1; i < ac; i++) {
		if (!is_arg_an_opt(av, i, optstring, long_options)) {
			/* Pushing ip in the IP list to scan */
			add_ip(av[i], &g_data.set);
		}
	}
	return 0;
}
