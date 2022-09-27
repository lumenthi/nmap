#ifndef OPTIONS_H
# define OPTIONS_H

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

/* parse_option_line.c */
int	parse_nmap_options(int ac, char **av);

#endif
