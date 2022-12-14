#ifndef OPTIONS_H
# define OPTIONS_H

#include <stdio.h>

#include "set.h"

# define OPT_VERBOSE_INFO		(1UL << 0)
# define OPT_VERBOSE_DEBUG		(1UL << 1)

/* Scan types */
# define OPT_SCAN_SYN			(1UL << 2)
# define OPT_SCAN_NULL			(1UL << 3)
# define OPT_SCAN_FIN			(1UL << 4)
# define OPT_SCAN_XMAS			(1UL << 5)
# define OPT_SCAN_ACK			(1UL << 6)
# define OPT_SCAN_UDP			(1UL << 7)
# define OPT_SCAN_TCP			(1UL << 8)

# define OPT_MODE_IP			(1UL << 9)
# define OPT_MODE_FILE			(1UL << 10)

# define OPT_SERVICE_DESC		(1UL << 11)
# define OPT_NO_PROGRESS		(1UL << 12)
# define OPT_ASCII_PROGRESS		(1UL << 13)

# define OPT_VERBOSE_PACKET		(1UL << 14)

# define OPT_DELAY				(1UL << 15)
# define OPT_NO_DISCOVERY		(1UL << 16)

# define FATAL_ERROR 2
# define PRINT_VERSION 3

# define MAX_PORT 1024
# define MAX_THREAD 255

# define DEFAULT_START_PORT 1
# define DEFAULT_END_PORT 1024

# define SCAN_VALID 0
# define SCAN_INVALID 1
# define SCAN_PRIVILEGES 2

# define FILE_VALID 0
# define FILE_INVALID 1
# define FILE_EXTENSION 2
# define EXTENSION ".ip"

/* main.c */
void init_data(void);

/* parse_option_line.c */
int	parse_nmap_args(int ac, char **av);

#endif
