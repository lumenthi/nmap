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
				char *str = strdup(arg + i);
				str[j] = 0;
				free(str);
				if (is_range == 1) {
					fprintf(stderr, "Error #486: Your port specifications are illegal." \
							"  Exemple of proper form: \"-100,200-1024\"\nQUITTING!\n");
					return 1;
				}
				set->nb_ranges++;
				j++;
				while (arg[j] >= '0' && arg[j] <= '9')
					j++;
				i = j;
				if (!arg[j])
					return 0;
			}
			else if (arg[j] == ',') {
				set->nb_single_values++;
				char *str = strdup(arg + i);
				str[j] = 0;
				free(str);
				if (arg[++j])
					i = j;
				if (!arg[j])
					return 0;
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
	printf("%ld ranges\n", set->nb_ranges);
	printf("%ld single values\n", set->nb_single_values);
	set->ranges = ft_memalloc(sizeof(t_range) * set->nb_ranges);
	if (!set->ranges) {
		set->nb_ranges = 0;
		perror("ft_nmap: ranges alloc");
	}
	set->single_values = ft_memalloc(sizeof(int) * set->nb_single_values);
	if (!set->single_values) {
		set->nb_single_values = 0;
		perror("ft_nmap: single values alloc");
	}
	printf("Parsing range 2 |%s|\n", arg);
	i = 0;
	while (arg[i]) {
		j = i;
		is_range = 0;
		while (arg[j]) {
			//printf("arg[j] = %c(%d)\n", arg[j], arg[j]);
			/* Each "," is a new range to parse */
			if (arg[j] == '-') {
				char *str = strdup(arg + i);
				str[j] = 0;
				printf("Current range str = |%s|\n", str);
				free(str);
				if (is_range == 1) {
					fprintf(stderr, "Error #486: Your port specifications are illegal." \
							"  Exemple of proper form: \"-100,200-1024\"\nQUITTING!\n");
					return 1;
				}
				is_range = 1;
				set->ranges[crange].start = ft_atoi(arg + i);
				if (arg[j + 1])
					set->ranges[crange].end = ft_atoi(arg + j + 1);
				else
					set->ranges[crange].end = set->max;
				crange++;
				//printf("Current range = [%d - %d]\n", curr_range->start, curr_range->end);
				j++;
				while (arg[j] >= '0' && arg[j] <= '9')
					j++;
				i = j;
				if (!arg[j])
					return 0;
			}
			else if (arg[j] == ',') {
				char *str = strdup(arg + i);
				str[j] = 0;
				printf("Current port = |%s|\n", str);
				free(str);
				set->single_values[csingle++] = ft_atoi(arg + i);
				if (arg[++j])
					i = j;
				if (!arg[j])
					return 0;
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

static int enable_scan(char *str, int str_len)
{
	char *scans[] = {"SYN", "NULL", "FIN", "XMAS", "ACK", "UDP", NULL};
	int i = 0; /* Start at SYN */

	while (scans[i]) {
		if (ft_strncmp(str, scans[i], str_len) == 0) {
			/* i+2 since our first scantype starts at 1UL<<2 in options.h */
			g_data.opt |= (1UL << (i+2));
			return 1;
		}
		i++;
	}
	return 0;
}

static int parse_scans(char *optarg)
{
	char *current = optarg;
	int curr_len;

	g_data.opt &= ~OPT_SCAN_SYN;

	while ((curr_len = get_next_scan(current))) {
		/* printf("[*] Current OPT: %s with size: %d\n",
			current, curr_len); */
		if (!(enable_scan(current, curr_len)))
			return 1;
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
	t_set	set;

	init_data(&curr_range);
	ft_bzero(&set, sizeof(set));

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
					if (parse_scans(optarg) != 0) {
						fprintf(stderr, "Invalid scan type\n");
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
					set.min = 1;
					set.max = MAX_PORT;
					parse_positive_range(&set, optarg);
					set_positive_range(&set, optarg);
					curr_range.start = ft_atoi(optarg);
					curr_range.end = ft_atoi(optarg);
					for (size_t k = 0; k < set.nb_ranges; k++)
						printf("Range %ld: [%d - %d]\n", k + 1,
							set.ranges[k].start, set.ranges[k].end);
					for (size_t k = 0; k < set.nb_single_values; k++)
						printf("Value %ld = %d\n", k + 1,
							set.single_values[k]);
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
			add_ip(av[i], &set);
		}
	}
	return 0;
}
