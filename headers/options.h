#ifndef OPTIONS_H
# define OPTIONS_H

#include <stdio.h>

# define OPT_VERBOSE_INFO		(1UL << 0)
# define OPT_VERBOSE_DEBUG		(1UL << 1)

//	Scan types
# define OPT_SCAN_SYN			(1UL << 2)
# define OPT_SCAN_NULL			(1UL << 3)
# define OPT_SCAN_FIN			(1UL << 4)
# define OPT_SCAN_XMAS			(1UL << 5)
# define OPT_SCAN_ACK			(1UL << 6)
# define OPT_SCAN_UDP			(1UL << 7)

# define OPT_MODE_IP			(1UL << 8)
# define OPT_MODE_FILE			(1UL << 9)

# define FATAL_ERROR 2
# define PRINT_VERSION 3

# define MAX_PORT 1024
# define MAX_THREAD 255

# define DEFAULT_START_PORT 1
# define DEFAULT_END_PORT 1024

typedef struct s_range {
	int					start;
	int					end;
	char				padding[0];
} t_range;

typedef struct s_set {
	size_t				nb_ranges;
	size_t				nb_single_values;
	t_range				*ranges;
	int					max;
	int					min;
	int					*single_values;
	char				padding[0];
} t_set;

/* main.c */
void init_data(t_range *port_range);

/* parse_option_line.c */
int	parse_nmap_args(int ac, char **av);

#endif
