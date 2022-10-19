#include "libft.h"
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

void	print_ip4_header(struct ip *header);
void	print_icmp_header(struct icmphdr *header);
void	print_tcp_header(struct tcphdr *header);
void	print_udp_header(struct udphdr *header);

#define PRINT_BITS(text_color, line_color) \
	fprintf(stderr, "+--+--+--+--+--+--+--+--+--+--+--+--+" \
	"--+--+--+--+--+--+--+--+--+--+--+--+" \
	"--+--+--+--+--+--+--+--+\n" \
	"|"text_color" 0"line_color"| "text_color"1"line_color"| "text_color"2" \
	line_color"| "text_color"3"line_color"| "text_color"4"line_color"| " \
	text_color"5"line_color"| "text_color"6"line_color"| "text_color \
	"7"line_color"| "text_color"8"line_color"| "text_color"9"line_color"|" \
	text_color"10"line_color"|"text_color"11"line_color"|"text_color"12" \
	line_color"|"text_color"13"line_color"|"text_color"14"line_color \
	"|"text_color"15"line_color"|"text_color"16"line_color"|"text_color"17" \
	line_color"|"text_color"18"line_color"|"text_color"19"line_color"|" \
	text_color"20"line_color"|"text_color"21"line_color"|"text_color \
	"22"line_color"|"text_color"23"line_color"|"text_color"24"line_color"|" \
	text_color"25|"text_color"26|"text_color"27|"text_color"28"line_color"|" \
	text_color"29"line_color"|"text_color"30"line_color"|"text_color"31" \
	line_color"|\n" \
	"+--+--+--+--+--+--+--+--+--+--+--+--+" \
	"--+--+--+--+--+--+--+--+--+--+--+--+" \
	"--+--+--+--+--+--+--+--+\n");

# define PACKET_COLOR_RESET		"\033[0m"
# define PACKET_COLOR_BOLD		"\033[1m"
# define PACKET_COLOR_UNDERLINE	"\033[4m"
# define PACKET_COLOR_BLINK		"\033[5m"
# define PACKET_COLOR_INVERT	"\033[7m"
# define PACKET_COLOR_CONCEALED	"\033[8m"

# define PACKET_COLOR_BLACK		"\033[30m"
# define PACKET_COLOR_RED		"\033[31m"
# define PACKET_COLOR_GREEN		"\033[32m"
# define PACKET_COLOR_YELLOW	"\033[33m"
# define PACKET_COLOR_BLUE		"\033[34m"
# define PACKET_COLOR_MAGENTA	"\033[35m"
# define PACKET_COLOR_CYAN		"\033[36m"
# define PACKET_COLOR_WHITE		"\033[37m"

# define PACKET_COLOR_BBLACK	"\033[40m"
# define PACKET_COLOR_BRED		"\033[41m"
# define PACKET_COLOR_BGREE		"\033[42m"
# define PACKET_COLOR_BYELLOW	"\033[43m"
# define PACKET_COLOR_BBLUE		"\033[44m"
# define PACKET_COLOR_BMAGENTA	"\033[45m"
# define PACKET_COLOR_BCYAN		"\033[46m"
# define PACKET_COLOR_BWHITE	"\033[47m"

#define LINE_LEN (32 * 3 + 1)

static void	print_line(const char *color)
{
	static char buff[LINE_LEN];

	for (int i = 0; i < LINE_LEN; i++)
		buff[i] = '-';
	fprintf(stderr, "\n%s%s\n", color, buff);
}

static void	print_last_line(const char *color)
{
	static char buff[LINE_LEN];

	for (int i = 0; i < LINE_LEN; i++)
		buff[i] = '-';
	buff[0] = '\\';
	buff[LINE_LEN - 1] = '/';
	fprintf(stderr, "\n%s%s\n", color, buff);
}

static void	print_title_line(const char *title, const char *text_color,
	const char *line_color)
{
	static char buff[LINE_LEN * 2]; /* x2 because of the potential color changes */
	size_t	len;
	size_t	half;

	len = ft_strlen(title);
	half = LINE_LEN / 2 - len / 2;
	//	Line color
	ft_memcpy(buff, line_color, 5);
	//	"/--------------"
	buff[5] = '/';
	for (size_t i = 6; i < half + 6; i++)
		buff[i] = '-';
	//	Text color
	ft_memcpy(buff + half + 5, text_color, 5);
	//	Title
	ft_memcpy(buff + half + 10, title, len);
	//	Line color
	ft_memcpy(buff + half + 10 + len, line_color, 5);
	//	"--------------\"
	for (size_t i = 15 + half + len; i < LINE_LEN - 1 + 15; i++)
		buff[i] = '-';
	buff[LINE_LEN - 1 + 15] = '\\';
	fprintf(stderr, "\n%s\n", buff);
}

static void print_value(int value, int value_len, size_t size, char specifier)
{
	int index;
	size_t	len;
	static char width[][10] = {
		"%-*hhd",
		"%-*hd",
		"%-*d",
		"%-*ld",
		"%-*lld"
	};

	if (size < 8)
		index = 0;
	else if (size < 16)
		index = 1;
	else
		index = 2;
	len = ft_strlen(width[index]);
	width[index][len - 1] = specifier;
	fprintf(stderr, width[index], value_len, value);
}

static void print_data(const char *name, int value, size_t size, char specifier,
	const char *text_color, const char *line_color)
{
	size_t	available_space;
	int	padding;
	int	value_len;

	available_space = size * 3 - 1;
	//fprintf(stderr, "\nName : %s\n", name);
	//fprintf(stderr, "available space = %ld\n", available_space);
	value_len = ft_getlen(ft_power(2, size)); 
	//fprintf(stderr, "name len = %ld\n", ft_strlen(name));
	//fprintf(stderr, "value len = %d\n", value_len);
	//	Final string = (space) + name + space + value + (space)
	padding = available_space - ft_strlen(name) - 1 - value_len;
	//fprintf(stderr, "padding = %d\n", padding);
	//fprintf(stderr, "left padding = %d\n", padding / 2);
	//fprintf(stderr, "right padding = %d\n|", (int)ft_ceil(padding / 2.0));
	fprintf(stderr, "%*s", (int)ft_ceil(padding / 2.0), "");
	fprintf(stderr, "%s%s ", text_color, name);
	print_value(value, value_len, size, specifier);
	fprintf(stderr, "%*s%s|", padding / 2, "", line_color);
}

static char	*get_ip(struct in_addr _addr)
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

static void	print_ip(const char *name, struct in_addr ip, const char *text_color,
	const char *line_color)
{
	char	*ip_str;
	char	*hostname;
	size_t	name_len;
	size_t	ip_len;
	size_t	hostname_len;
	size_t	padding;

	ip_str = inet_ntoa(ip);
	hostname = get_ip(ip);
	name_len = ft_strlen(name);
	ip_len = ft_strlen(ip_str);
	hostname_len = ft_strlen(hostname);
	padding = LINE_LEN - name_len - 1 - hostname_len - 1 - ip_len - 2 - 2;
	fprintf(stderr, "%s|%*s%s", line_color, (int)padding / 2, "", text_color);
	fprintf(stderr, "%s %s (%s)", name, hostname, ip_str);
	fprintf(stderr, "%*s%s|", (int)ft_ceil(padding / 2.0), "", line_color);
}

static void	print_tcp_flags(struct tcphdr *header, const char *text_color,
	const char *line_color)
{
	int	count;
	int	first;
	int padding;

	count = 0;
	if (header->th_flags & TH_FIN)
		count++;
	if (header->th_flags & TH_SYN)
		count++;
	if (header->th_flags & TH_RST)
		count++;
	if (header->th_flags & TH_PUSH)
		count++;
	if (header->th_flags & TH_ACK)
		count++;
	if (header->th_flags & TH_URG)
		count++;
	padding = 9 * 3 - 1 - (count * 4 - 1);
	fprintf(stderr, "%*s%s", padding / 2, "", text_color);
	first = 0;
	if (header->th_flags & TH_FIN) {
		if (first > 0)
			fprintf(stderr, "/");
		fprintf(stderr, "FIN");
		first++;
	}
	if (header->th_flags & TH_SYN) {
		if (first > 0)
			fprintf(stderr, "/");
		fprintf(stderr, "SYN");
		first++;
	}
	if (header->th_flags & TH_RST) {
		if (first > 0)
			fprintf(stderr, "/");
		fprintf(stderr, "RST");
		first++;
	}
	if (header->th_flags & TH_PUSH) {
		if (first > 0)
			fprintf(stderr, "/");
		fprintf(stderr, "PUSH");
		first++;
	}
	if (header->th_flags & TH_ACK) {
		if (first > 0)
			fprintf(stderr, "/");
		fprintf(stderr, "ACK");
		first++;
	}
	if (header->th_flags & TH_URG) {
		if (first > 0)
			fprintf(stderr, "/");
		fprintf(stderr, "URG");
		first++;
	}
	fprintf(stderr, "%*s%s|", (int)ft_ceil(padding / 2.0), "", line_color);
}

void	print_ip4_header(struct ip *header)
{
	print_title_line("IP", PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);
	PRINT_BITS(PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);

	fprintf(stderr, "|");
	print_data("Version", header->ip_v, 4, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);
	print_data("IHL", header->ip_hl, 4, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);
	print_data("TOS", header->ip_tos , 8, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);
	print_data("Total len", ntohs(header->ip_len), 16, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);

	print_line(PACKET_COLOR_GREEN);

	fprintf(stderr, "|");
	print_data("Identification", ntohs(header->ip_id), 16, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);
	print_data("Fragment offset", ntohs(header->ip_off), 16, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);

	print_line(PACKET_COLOR_GREEN);

	fprintf(stderr, "|");
	print_data("TTL", header->ip_ttl, 8, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);
	print_data("Protocol", header->ip_p, 8, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);
	print_data("Checksum", ntohs(header->ip_sum) , 16, 'x',
		PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);
	
	print_line(PACKET_COLOR_GREEN);
	print_ip("Source address", header->ip_src, PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);
	print_line(PACKET_COLOR_GREEN);
	print_ip("Destination address", header->ip_dst, PACKET_COLOR_YELLOW, PACKET_COLOR_GREEN);
	print_last_line(PACKET_COLOR_GREEN);
	fprintf(stderr, PACKET_COLOR_RESET);

	//	Only print next headers if there are no options
	if (header->ip_hl > 5)
		return;
	switch (header->ip_p) {
		case 1:
			print_icmp_header((struct icmphdr*)(header + 1));
			break;
		case 6:
			print_tcp_header((struct tcphdr*)(header + 1));
			break;
		case 17:
			print_udp_header((struct udphdr*)(header + 1));
			break;
		default:
			break;
	}
}

void	print_icmp_header(struct icmphdr *header)
{
	print_title_line("ICMP", PACKET_COLOR_YELLOW, PACKET_COLOR_CYAN);
	PRINT_BITS(PACKET_COLOR_YELLOW, PACKET_COLOR_CYAN);

	fprintf(stderr, "|");
	print_data("Type", header->type, 8, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_CYAN);
	print_data("Code", header->code, 8, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_CYAN);
	print_data("Checksum", header->type, 16, 'x',
		PACKET_COLOR_YELLOW, PACKET_COLOR_CYAN);
	
	print_line(PACKET_COLOR_CYAN);

	fprintf(stderr, "|");
	print_data("ID", ntohs(header->un.echo.id), 16, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_CYAN);
	print_data("Sequence", ntohs(header->un.echo.sequence), 16, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_CYAN);

	print_last_line(PACKET_COLOR_CYAN);
	fprintf(stderr, PACKET_COLOR_RESET);
}

void	print_udp_header(struct udphdr *header)
{
	print_title_line("UDP", PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);
	PRINT_BITS(PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);

	fprintf(stderr, "|");
	print_data("Source port", ntohs(header->uh_sport), 16, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);
	print_data("Destination port", ntohs(header->uh_dport), 16, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);

	print_line(PACKET_COLOR_MAGENTA);

	fprintf(stderr, "|");
	print_data("Length", ntohs(header->uh_ulen), 16, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);
	print_data("Checksum", ntohs(header->uh_sum), 16, 'x',
		PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);

	print_last_line(PACKET_COLOR_MAGENTA);
	fprintf(stderr, PACKET_COLOR_RESET);
}

void	print_tcp_header(struct tcphdr *header)
{	
	print_title_line("TCP", PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);
	PRINT_BITS(PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);

	fprintf(stderr, "|");
	print_data("Source port", ntohs(header->th_sport), 16, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);
	print_data("Destination port", ntohs(header->th_dport), 16, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);

	print_line(PACKET_COLOR_MAGENTA);

	fprintf(stderr, "|");
	/* TODO: Why does this not work */
	print_data("Sequence number", ntohl(header->th_seq), 32, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);

	print_line(PACKET_COLOR_MAGENTA);

	fprintf(stderr, "|");
	print_data("Acknowledgment number", ntohl(header->th_ack), 32, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);

	print_line(PACKET_COLOR_MAGENTA);

	fprintf(stderr, "|");
	print_data("Off", ntohs(header->th_ack), 7, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);
	print_tcp_flags(header, PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);
	print_data("Window size", ntohs(header->th_win), 16, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);

	print_line(PACKET_COLOR_MAGENTA);

	fprintf(stderr, "|");
	print_data("Checksum", ntohs(header->th_sum), 16, 'x',
		PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);
	print_data("Urgent pointer", ntohs(header->th_urp), 16, 'u',
		PACKET_COLOR_YELLOW, PACKET_COLOR_MAGENTA);

	if (header->th_off > 5)
		print_line(PACKET_COLOR_MAGENTA);
	// Options
	for (int i = 0; i < header->th_off - 5; i++)
	{
		struct tcp_opt {
			uint8_t	kind;
			uint8_t	len;
			uint8_t	data1;
			uint8_t	data2;
		} *opt;

		opt = (struct tcp_opt*)((void*)header + sizeof(struct tcphdr) + i * 4);
		fprintf(stderr, "\e[35m|\e[33m   TCP Option (%hhu)", opt->kind);
		fprintf(stderr, " Len = %hhu", opt->len);
		fprintf(stderr, " Value = 0x%0x%0x", opt->data1, opt->data2);
		fprintf(stderr, " \e[35m|");
	}

	print_last_line(PACKET_COLOR_MAGENTA);
	
	fprintf(stderr, PACKET_COLOR_RESET);
}
