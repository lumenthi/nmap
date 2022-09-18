#ifndef NMAP_H
# define TRACEROUTE_H

#include "libft.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

typedef struct	s_data {
	uint8_t				args;
	char				*path;
	char				ipv4[INET_ADDRSTRLEN];
	struct addrinfo		*host_info;

	struct sockaddr		*host_addr;
	struct sockaddr_in	servaddr;

	char				*address;

}						t_data;

/* nmap.c */
int		ft_nmap(char *destination, uint8_t args,
	char *path);

#endif
