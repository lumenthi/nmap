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
#include <netinet/tcp.h>

/* struct hostent {
	char	*h_name;				host name
	char	**h_aliases;			array pointer to alternative hostanmaes
	int		h_addrtype;				host address type
	int		h_length;				length of address
	char	**h_addr_list;			array pointer to network addresses
	#define h_addr h_addr_list[0]	for backward compatibility
} */

/* struct sockaddr {
	ushort	sa_family;
	char	sa_data[14];
}; */

/* struct sockaddr_in {
	short			sin_family;
	u_short			sin_port;
	struct in_addr	sin_addr;
	char			sin_zero[8];
}; */

typedef struct	s_data {
	uint8_t				args;
	char				*path;
	char				ipv4[INET_ADDRSTRLEN];
	struct addrinfo		*host_info;

	struct sockaddr		*host_addr;
	struct sockaddr_in	servaddr;

	char				*address;

}						t_data;

/* struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int	ihl:4;
	unsigned int	version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int	version:4;
	unsigned int	ihl:4;
#else
# error        "Please fix <bits/endian.h>"
#endif
	u_int8_t	tos;
	u_int16_t	tot_len;
	u_int16_t	id;
	u_int16_t	frag_off;
	u_int8_t	ttl;
	u_int8_t	protocol;
	u_int16_t	check;
	u_int32_t	saddr;
	u_int32_t	daddr;
}; */

/* struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1, FLAGS
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
}; */

/* nmap.c */
int		ft_nmap(char *destination, uint8_t args,
	char *path);

#endif
