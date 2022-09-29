#include "nmap.h"

static char	*print_ip(struct in_addr _addr)
{
	struct sockaddr_in	addr =
	{
		AF_INET,
		0,
		_addr,
		{ 0 }
	};
	static char	host[512];
	ft_bzero(host, sizeof(host));
	if (getnameinfo((struct sockaddr*)&addr, sizeof(struct sockaddr),
			host, sizeof(host), NULL, 0, 0))
		return inet_ntoa(addr.sin_addr);
	return host;
}

void	print_ip4_header(struct ip *header)
{
	printf("\e[32m+----------------------+----IP-----+------------------+\n");
	//	Version
	printf("\e[32m|\e[33m  Version %-2hhu \e[32m/\e[33m", header->ip_v);
	//	IHL
	printf(" IHL %-2hhu \e[32m|\e[33m", header->ip_hl);
	//	Type of service
	printf("   TOS %-3hx \e[32m|\e[33m", header->ip_tos);
	//	Total length
	printf("  Total len %-5hd \e[32m|\n", ntohs(header->ip_len));

	printf("\e[32m+----------------------+-+---------+------------------+\n");

	//	Identification
	printf("\e[32m|\e[33m         ID %-5hu       \e[32m|\e[33m",
		ntohs(header->ip_id));
	//	Flags / Offset
	printf("         Offset %-5hu       \e[32m|\n", ntohs(header->ip_off));

	printf("\e[32m+--------------+---------+--------+-------------------+\n");

	//	TTL
	printf("\e[32m|\e[33m    TTL %-3hhu   \e[32m|\e[33m", header->ip_ttl);
	//	Protocol
	printf("    Protocol %-3hhu  \e[32m|\e[33m", header->ip_p);
	//	Header cheskum
	printf("   Checksum %-5hx  \e[32m|\n", ntohs(header->ip_sum));

	printf("\e[32m+--------------+------------------+-------------------+\n");

	struct in_addr	*addr = &header->ip_src;
	printf("\e[32m|\e[33m       Source addr %s (%s)      \e[32m|\n",
		inet_ntoa(*addr), print_ip(*addr));

	printf("\e[32m+-----------------------------------------------------+\n");

	addr = &header->ip_dst;
	printf("\e[32m|\e[33m       Dest addr %s (%s)        \e[32m|\n",
		inet_ntoa(*addr), print_ip(*addr));

	printf("\e[32m+-----------------------------------------------------+\e[0m\n");
}

void	print_tcp_header(struct tcphdr *header)
{
	printf("\e[35m+--------------+------TCP------+-------------+\n");

	//	Source port
	printf("\e[35m|\e[33m   Source port %-5hu  \e[35m|\e[33m", ntohs(header->th_sport));
	//	Dest port
	printf("   Dest port %-5hu   \e[35m|\n", ntohs(header->th_dport));

	printf("\e[35m+----------------------+---------------------+\n");

	//	Sequence number
	printf("\e[35m|\e[33m   Sequ number %-5u  \e[35m|\e[33m", ntohs(header->th_seq));
	//	Ack number
	printf("    Ack number %-5x \e[35m|\n", ntohs(header->th_ack));

	printf("\e[35m+----------------------+---------------------+\n");

	//	Flags
	printf("\e[35m|\e[33m   Flags ");
	if (header->th_flags & TH_FIN)
		printf("/FIN");
	if (header->th_flags & TH_SYN)
		printf("/SYN");
	if (header->th_flags & TH_RST)
		printf("/RST");
	if (header->th_flags & TH_PUSH)
		printf("/PUSH");
	if (header->th_flags & TH_ACK)
		printf("/ACK");
	if (header->th_flags & TH_URG)
		printf("/URG");
	//	Window size
	printf(" \e[35m|\e[33m    Winsize %-5d \e[35m|\n", ntohs(header->th_win));

	printf("\e[35m+----------------------+---------------------+\n");

	//	Checksum
	printf("\e[35m|\e[33m   Checksum %-5x  \e[35m|\e[33m", ntohs(header->th_sum));
	//	Urgent pointer
	printf("    Urgent pointer %-5d \e[35m|\n", ntohs(header->th_urp));

	printf("\e[35m+----------------------+---------------------+\n");

	printf("\e[35m+--------------------------------------------+\e[0m\n");
}

void print_time(struct timeval start_time, struct timeval end_time)
{
	long int sec = end_time.tv_sec - start_time.tv_sec;
	long int usec = end_time.tv_usec - start_time.tv_usec;
	long long total_usec = sec*1000000+usec;

	printf("[*] Scan time: %lld.%03lld ms\n",
		total_usec/1000, total_usec%1000);
}
