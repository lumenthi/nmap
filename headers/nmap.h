#ifndef NMAP_H
# define NMAP_H

#include "libft.h"
#include "set.h"

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
#include <linux/in.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>

/* DATABASE */
#define DB_PATH "/tmp/ft_nmap/"

/* SERVICES */
#define SERVICES_FILENAME "services"
#define DB_SERVICES DB_PATH SERVICES_FILENAME

/* PAYLOADS */
#define PAYLOADS_FILENAME "payloads"
#define DB_PAYLOADS DB_PATH PAYLOADS_FILENAME

/* ASCII ART */
#define ASCII_FILENAME "art.ascii"
#define DB_ASCII DB_PATH ASCII_FILENAME

/* STATUS */
#define OPEN 0
#define CLOSED 1
#define FILTERED 2
#define OPEN_FILTERED 3
#define UNFILTERED 4
#define DOWN 5
#define ERROR 6
#define UNKNOWN 7
#define TIMEOUT 8
#define UP 9
#define READY 10
#define PRINTED 11
#define SCANNING 12
#define INVALID 13
#define IN_USE 14
#define FREE 15

#define UPDATE 1
#define UPDATE_TARGET 2
#define ALREADY_UPDATED 3

/* Max ips to scan in one command */
#define MAX_IPS 15

/* Default ephemeral ports */
#define DEFAULT_EPHEMERAL_MIN 32768
#define DEFAULT_EPHEMERAL_MAX 60999

#define LOCK(input)		pthread_mutex_lock(&input->lock);
#define UNLOCK(input)	pthread_mutex_unlock(&input->lock);

struct s_scan {
	struct sockaddr_in	saddr; /* sockaddr_in of source */
	struct sockaddr_in	daddr; /* sockaddr_in of dest */
	char				*dhostname; /* found destination hostname */
	int					scantype; /* Type of scan */
	int					status; /* Current status [READY/SCANNING/OPEN/CLOSED/FILTERED] */
	char				*service; /* Service running on this port */
	char				*service_desc; /* Small description of the service running on this port */
	uint16_t			sport; /* Source port */
	uint16_t			dport; /* Destination port */
	struct timeval		start_time; /* Scan start time */
	struct timeval		end_time; /* Scan end time */

	pthread_mutex_t		lock; /* Mutex */
};

struct port {
	char	*tcp_name;
	char	*tcp_desc;

	char	*udp_name;
	char	*udp_desc;

	/* UDP payload */
	char	*payload;
	size_t	payload_len;

	/* Is this port currently used for sending */
	int		status;
};

struct s_port {
	/* All scans for a port */
	struct s_scan *syn_scan;
	struct s_scan *null_scan;
	struct s_scan *fin_scan;
	struct s_scan *xmas_scan;
	struct s_scan *ack_scan;
	struct s_scan *udp_scan;
	struct s_scan *tcp_scan;

	int final_status; /* Final status after combining every scan type's result */
};

struct s_ip {
	struct sockaddr_in	*saddr; /* sockaddr_in of source */
	struct sockaddr_in	*daddr; /* sockaddr_in of dest */
	int64_t				srtt;
	int64_t				rttvar;
	struct timeval		timeout; /* Time to wait until timeout (determined by host discovery) */
	char				*dhostname; /* found ip hostname */
	char				*destination; /* user input */
	int					status; /* [UP/DOWN/ERROR] */
	struct s_port		ports[USHRT_MAX+1]; /* All ports for an IP */
	pthread_mutex_t		lock; /* Mutex */

	struct s_ip			*next; /* next ip */
};

struct s_tmp_ip {
	struct sockaddr_in	saddr; /* sockaddr_in of source */
	struct sockaddr_in	daddr; /* sockaddr_in of dest */
	int64_t				srtt;
	int64_t				rttvar;
	struct timeval		timeout; /* Time to wait until timeout (determined by host discovery) */
	char				*destination;
	char				*dhostname;
	int					status;
	pthread_mutex_t		lock; /* Mutex */
	struct s_tmp_ip		*next;
};

typedef struct	s_data {
	/* Options related */
	unsigned long long	opt;
	t_set				set;
	t_ipset				*ipset;

	/* Scan list */
	struct s_ip			*ips;

	/* Down ips */
	struct s_tmp_ip		*tmp_ips;
	struct in_addr		*down_ips;
	int					nb_down_ips;

	/* Threads related */
	pthread_t			*threads;
	uint8_t				nb_threads;
	int					created_threads;

	/* Ephemeral ports */
	uint16_t			port_min;
	uint16_t			port_max;

	/* Is program run as root */
	uint8_t				privilegied;

	/* Ports services and status */
	struct port			*ports;

	/* Diplay related */
	pthread_mutex_t		print_lock;

	/* Dynamic timeout */
	struct timeval		max_rtt;
	struct timeval		min_rtt;
	struct timeval		initial_rtt;
	uint64_t			delay;

	long				max_ips;

	/* Counters */
	int					ip_counter;
	int					vip_counter; /* valid ips counter */
	int					port_counter;
	int					scan_types_counter;
	int					total_scan_counter;
	int					finished_scans;
}						t_data;

struct			tcp_options {
};

struct			ip_options {
};

struct			tcp_packet {
	struct iphdr		ip;
	struct tcphdr		tcp;
};

struct			udp_packet {
	struct iphdr		ip;
	struct udphdr		udp;
};

struct			icmp_packet {
	struct iphdr		ip;
	struct icmphdr		icmp;
	union {
		struct tcp_packet	tcp;
		struct udp_packet	udp;
	};
};

extern t_data	g_data;

/* help.c */
void	print_version(void);
void	print_usage(FILE* f);
void	print_help();

/* print.c */
void	print_ip4_header(struct ip *header);
void	print_udp_header(struct udphdr *header);
void	print_time(struct timeval start_time, struct timeval end_time,
			struct timeval sstart_time, struct timeval send_time);
void	print_scans(struct s_ip *ips);

/* syn_scan.c */
int		syn_scan(struct s_scan *to_scan, struct s_port *ports,
	struct timeval timeout);
/* udp_scan.c */
int		udp_scan(struct s_scan *to_scan, struct s_port *ports,
	struct timeval timeout);
/* fin_scan.c */
int		fin_scan(struct s_scan *to_scan, struct s_port *ports,
	struct timeval timeout);
/* null_scan.c */
int		null_scan(struct s_scan *to_scan, struct s_port *ports,
	struct timeval timeout);
/* xmas_scan.c */
int		xmas_scan(struct s_scan *to_scan, struct s_port *ports,
	struct timeval timeout);
/* xmas_scan.c */
int		ack_scan(struct s_scan *to_scan, struct s_port *ports,
	struct timeval timeout);
/* tcp_scan.c */
int		tcp_scan(struct s_scan *to_scan,
	struct timeval timeout);

/* addr_config.c */
int dconfig(char *destination, uint16_t port, struct sockaddr_in *daddr,
	char **hostname);
int		sconfig(char *destination, struct sockaddr_in *saddr);

/* checksum.c */
unsigned short tcp_checksum(struct iphdr *ip, struct tcphdr *tcp);
unsigned short checksum(const char *buf, unsigned int size);

/* parse_file.c */
void	free_ipset(t_ipset **ipset);
int		parse_file(char *path, t_ipset **head);

/* parse_option_line.c */
void	print_usage(FILE* f);

/* nmap.c */
int		ft_nmap(char *path, struct timeval *start, struct timeval *end);

/* free_and_exit.c */
void	free_and_exit(int exit_val);

/* craft_packet.c */
void	craft_ip_packet(void *packet, struct sockaddr_in *saddr,
	struct sockaddr_in *daddr, uint8_t protocol, struct ip_options *options);
void	craft_tcp_packet(void *packet, struct sockaddr_in *saddr,
	struct sockaddr_in *daddr, uint8_t flags, struct tcp_options *options);
void	craft_udp_packet(void *packet, struct sockaddr_in *saddr,
	struct sockaddr_in *daddr, char *payload, uint16_t payload_len);
void	craft_icmp_packet(void *packet, uint8_t type, uint8_t code,
	uint16_t id, uint16_t sequence, char *payload, uint16_t payload_len);

/* services.c */
int		get_services(void);
void	free_services(void);

/* payload.c */
int		get_payloads(void);
void	free_payloads(void);

/* list.c */
void	print_progress(void);
int update_scans(struct s_scan *scan, struct s_port *ports, int status,
	uint16_t source_port, uint16_t dest_port);
void	push_ip(struct s_ip **head, struct s_ip *new);
void	push_ports(struct s_ip **input, t_set *set);
void	free_ips(struct s_ip **ip);
int		assign_port(uint16_t min, uint16_t max);
void	add_tmp_ip(char *ip_string);
int		add_ip_range(char *destination, char *slash, t_set *set);
void	add_ip(struct s_tmp_ip *ip, t_set *set);
void	print_ip_list(struct s_ip *ips);
void	remove_ip(struct s_ip **ips, struct s_ip *ip);

/* timedout.c */
int		timed_out(struct timeval start, struct timeval timeout, int status);

/* host_discovery.c */
int		host_discovery(void);

#endif
