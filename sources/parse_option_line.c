#include "options.h"
#include "libft.h"
#include "nmap.h"
#include <stdio.h>

typedef struct s_range {
	int					start;
	int					end;
	char				padding[0];
} t_range;

typedef struct s_set {
	size_t				nb_ranges;
	size_t				nb_single_values;
	t_range				*ranges;
	int					min;
	int					max;
	int					*single_values;
	char				padding[0];
} t_set;

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

int			parse_positive_range(t_set *set, char *arg, t_range *curr_range)
{
	size_t	i, j;
	int		is_range;

	i = 0;
	while (arg[i]) {
		j = i;
		is_range = 0;
		curr_range->start = 0;
		curr_range->end = 0;
		while (arg[j] && arg[j] != ',') {
			if (arg[j] == '-') {
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
			}
			j++;
		}
		i++;
	}
	return 0;
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
	struct s_ip *tmp;

	/* TODO: 1 - 1024 default values */
	curr_range.start = 1;
	curr_range.end = 22;

	while ((opt = ft_getopt_long(ac, av, optstring, &optarg,
					long_options, &option_index)) != -1) {
		switch (opt) {
			case 'v':
				/* TODO: optional argument for short options */
				g_data.opt |= OPT_VERBOSE_INFO;
				if (optarg != NULL) {
					printf("optarg = %s\n", optarg);
					if (ft_strcmp(optarg, "DEBUG") == 0) {
						g_data.opt |= OPT_VERBOSE_DEBUG;
						g_data.opt &= ~OPT_VERBOSE_INFO;
					}
					else if (ft_strcmp(optarg, "INFO") == 0)
						g_data.opt |= OPT_VERBOSE_INFO;
					else
						fprintf(stderr, "Invalid verbose level\n");
				}
				break;
			case 'i':
				{
					/* g_data.destination = ft_strdup(optarg);
					if (g_data.destination == NULL)
					{
						perror("ft_nmap: ft_strdup");
						free_and_exit(EXIT_FAILURE);
					} */
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
			/* TODO: Check malloc ret */
			tmp = (struct s_ip *)malloc(sizeof(struct s_ip));
			ft_memset(tmp, 0, sizeof(struct s_ip));
			tmp->destination = av[i];
			push_ports(&tmp, curr_range.start, curr_range.end);
			push_ip(&g_data.ips, tmp);
		}
	}
	return 0;
}
