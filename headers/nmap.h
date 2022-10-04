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
#include <fcntl.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <pthread.h>

/* STATUS */
#define OPEN 0
#define CLOSED 1
#define FILTERED 2
#define DOWN 3
#define ERROR 4
#define UNKNOWN 5
#define TIMEOUT 6
#define UP 7
#define READY 8
#define PRINTED 9
#define SCANNING 10
#define INVALID 11

/* Default ephemeral ports */
#define DEFAULT_EPHEMERAL_MIN 32768
#define DEFAULT_EPHEMERAL_MAX 60999

/* https://man7.org/linux/man-pages/man7/netdevice.7.html */
/* struct ifaddrs
{
	struct ifaddrs	*ifa_next;		Pointer to the next structure.
	char			*ifa_name;		Name of this network interface.
	unsigned int	ifa_flags;		Flags as from SIOCGIFFLAGS ioctl.
	struct sockaddr	*ifa_addr;		Network address of this interface.
	struct sockaddr	*ifa_netmask;	Netmask of this interface.
	union
	{
		At most one of the following two is valid.  If the IFF_BROADCAST
			bit is set in `ifa_flags', then `ifa_broadaddr' is valid.  If the
			IFF_POINTOPOINT bit is set, then `ifa_dstaddr' is valid.
			It is never the case that both these bits are set at once.
		struct sockaddr	*ifu_broadaddr;	Broadcast address of this interface.
		struct sockaddr	*ifu_dstaddr;	Point-to-point destination address.
	} ifa_ifu;
	These very same macros are defined by <net/if.h> for `struct ifaddr'.
		So if they are defined already, the existing definitions will be fine.
# ifndef ifa_broadaddr
#  define ifa_broadaddr	ifa_ifu.ifu_broadaddr
# endif
# ifndef ifa_dstaddr
#  define ifa_dstaddr	ifa_ifu.ifu_dstaddr
# endif
	void *ifa_data;		Address-specific data (may be unused).
}; */

/* struct hostent {
	char	*h_name;				host name
	char	**h_aliases;			array pointer to alternative hostnames
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

typedef struct s_range {
	uint16_t			start;
	uint16_t			end;
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

struct s_scan {
	struct sockaddr_in	*saddr; /* sockaddr_in of source */
	struct sockaddr_in	*daddr; /* sockaddr_in of dest */
	char				*dhostname; /* found destination hostname */
	int					scantype; /* Type of scan */
	int					status; /* Current status [READY/SCANNING/OPEN/CLOSED/FILTERED] */
	char				*service; /* Found service */
	uint16_t			sport; /* Source port */
	uint16_t			dport; /* Destination port */
	struct timeval		start_time; /* Scan start time */
	struct timeval		end_time; /* Scan end time */
	struct s_scan		*next; /* Next scan */
};

struct s_ip {
	struct sockaddr_in	*saddr; /* sockaddr_in of source */
	struct sockaddr_in	*daddr; /* sockaddr_in of dest */
	char				*dhostname; /* found ip hostnme */
	char				*destination; /* user input */
	int					status; /* [UP/DOWN/ERROR] */
	struct s_scan		*scans; /* list of ports to scan along with the type of scan */
	struct s_ip			*next; /* next ip */
};

typedef struct	s_data {
	unsigned long long	opt;
	struct s_ip			*ips;
	uint8_t				nb_threads;
	int					created_threads;
	uint16_t			port_min;
	uint16_t			port_max;
	pthread_t			*threads;
}						t_data;

struct			tcp_packet {
	struct iphdr		ip;
	struct tcphdr		tcp;
};

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

extern t_data	g_data;

/* print.c */
void	print_ip4_header(struct ip *header);
void	print_time(struct timeval start_time,
	struct timeval end_time);
void	print_scans(struct s_ip *ips);

/* scan_syn.c */
int		syn_scan(struct s_scan *to_scan);

/* addr_config.c */
int dconfig(char *destination, uint16_t port, struct sockaddr_in *daddr,
	char **hostname);
int		sconfig(char *destination, struct sockaddr_in *saddr);

/* checksum.c */
unsigned short tcp_checksum(struct iphdr *ip, struct tcphdr *tcp);
unsigned short checksum(const char *buf, unsigned int size);

/* parse_option_line.c */
void print_usage(FILE* f);

/* nmap.c */
int		ft_nmap(char *path);

/* free_and_exit.c */
void	free_and_exit(int exit_val);

/* list.c */
void	push_ip(struct s_ip **head, struct s_ip *new);
void	push_ports(struct s_ip **input, t_set *set);
void	free_ips(struct s_ip **ip);

#endif
