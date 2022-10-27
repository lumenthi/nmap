#include "nmap.h"
#include "options.h"
#include "colors.h"
#include <math.h>

#define BAR_SIZE 70
#define R 0
#define G 1
#define B 2

void add_ip(char *ip_string, t_set *set)
{
	struct s_ip *tmp;

	tmp = (struct s_ip *)malloc(sizeof(struct s_ip));
	if (tmp) {
		ft_memset(tmp, 0, sizeof(struct s_ip));
		tmp->destination = ip_string;
		/* Default status */
		tmp->status = UP;
		/* Prepare addr structs */
		tmp->saddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		tmp->daddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		if (!tmp->saddr || !tmp->daddr)
			tmp->status = ERROR;
		if (dconfig(tmp->destination, 0, tmp->daddr, &tmp->dhostname) != 0)
			tmp->status = DOWN;
		if (sconfig(inet_ntoa(tmp->daddr->sin_addr), tmp->saddr) != 0)
			tmp->status = ERROR;
		if (tmp->status == UP) {
			push_ports(&tmp, set);
			++g_data.vip_counter;
		}
		tmp->srtt = 0;
		tmp->rttvar = 0;
		tmp->timeout = 1345678;
		push_ip(&g_data.ips, tmp);
	}
}

int	add_ip_range(char *destination, char *slash, t_set *set)
{
	/* TODO: error if not 0 < mask < 32 */
	int maskarg = ft_atoi(slash + 1);
	uint32_t mask = 0;
	uint32_t nmask;
	uint32_t nb_hosts;
	for (int i = 0; i < maskarg; i++)
		mask |= (1 << (31 - i));
	mask = htonl(mask);
	nmask = ~mask;
	(void)nmask;
	//printf("mask = %u\n", ntohs(mask));
	//printf("~mask = %u\n", ntohs(nmask));
	struct in_addr imask;
	ft_memcpy(&imask, &mask, sizeof(mask));
	//printf("\nIP mask = %s\n", inet_ntoa(imask));
	if (maskarg == 32)
		nb_hosts = 1;
	else if (maskarg == 31)
		nb_hosts = 2;
	else
		nb_hosts = ft_power(2, 32 - maskarg);

	struct hostent *host;
	*slash = 0;
	if (!(host = gethostbyname(destination)))
		return 1;
	*slash = '/';
	struct in_addr hia, nia;
	ft_memcpy(&nia, host->h_addr_list[0], host->h_length);
	//printf("\nStart ip = %s\n", inet_ntoa(nia));
	nia.s_addr &= mask;
	hia.s_addr = ntohl(nia.s_addr);
	for (uint32_t i = 0; i < nb_hosts; i++) {
		nia.s_addr = htonl(hia.s_addr);
		//if (hostname)
		//	*hostname = ft_strdup(inet_ntoa(nia));
		add_ip(inet_ntoa(nia), set);
		++g_data.ip_counter;
		/*if (++g_data.ip_counter > MAX_IPS) {
			fprintf(stderr, "Max ip limit reached (%d)\n", MAX_IPS);
			return 1;
		}*/
		//printf("ip = %s\n", inet_ntoa(nia));
		hia.s_addr++;
	}
	return 0;
}

void	print_progress()
{
	pthread_mutex_lock(&g_data.print_lock);
	g_data.finished_scans++;
	float progress = 100.0f * g_data.finished_scans / (float)g_data.total_scan_counter;

	/* ASCII */
	if (g_data.opt & OPT_ASCII_PROGRESS) {
		printf("\r[");
		for (int_fast32_t i = 0; i < floor(progress / 2); i++)
			printf("|");
		for (int_fast32_t i = 0; i < 50 - floor(progress / 2); i++)
			printf("-");
		printf("] %.2f%%", progress);
	}
	else {
		printf("\r|");
		int start[3] = {0xbd, 0xc3, 0xc7};
		int end[3] = {0x2c, 0x3e, 0x50};
		for (int_fast32_t i = 0; i < floor(progress / 2); i++) {
			printf("\e[48;2;%d;%d;%dm ",
				(int)(i / 50.0f * (end[R] - start[R])) + start[R],
				(int)(i / 50.0f * (end[G] - start[G])) + start[G],
				(int)(i / 50.0f * (end[B] - start[B])) + start[B]
				);
		}
		printf(NMAP_COLOR_RESET);
		for (int_fast32_t i = 0; i < 50 - floor(progress / 2); i++)
			printf(" ");

		printf("| %.2f%%", progress);
	}
	fflush(stdout);
	if (g_data.opt & OPT_VERBOSE_DEBUG || g_data.opt & OPT_VERBOSE_PACKET)
		fprintf(stderr, "\n");
	pthread_mutex_unlock(&g_data.print_lock);
}

/* Update scan with port `source_port`
 * returns UPDATE_TARGET if our target scan `scan` is updated
 * returns UPDATE if we update another scan than target scan `scan` */
int update_scans(struct s_scan *scan, struct s_port *ports, int status,
	uint16_t source_port, uint16_t dest_port)
{
	source_port = ntohs(source_port);
	dest_port = ntohs(dest_port);

	struct s_port port = ports[dest_port];
	struct s_scan *tmp = NULL;

	int ret = 0;

	switch (scan->scantype) {
		case OPT_SCAN_SYN:
			tmp = port.syn_scan;
			break;
		case OPT_SCAN_NULL:
			tmp = port.null_scan;
			break;
		case OPT_SCAN_FIN:
			tmp = port.fin_scan;
			break;
		case OPT_SCAN_XMAS:
			tmp = port.xmas_scan;
			break;
		case OPT_SCAN_ACK:
			tmp = port.ack_scan;
			break;
		case OPT_SCAN_UDP:
			tmp = port.udp_scan;
			break;
		case OPT_SCAN_TCP:
			tmp = port.tcp_scan;
			break;
		return 0;
	}

	if (!tmp)
		return 0;

	LOCK(tmp);
	if ((tmp->status == SCANNING || tmp->status == TIMEOUT) &&
		tmp->sport == source_port && tmp->dport == dest_port)
	{
		if (tmp == scan) {
			tmp->status = status;
			ret = UPDATE_TARGET;
		}
	}
	UNLOCK(tmp);
	return ret;
}

static void	free_port(struct s_port *port)
{
	if (port->syn_scan) {
		free(port->syn_scan);
		port->syn_scan = NULL;
	}
	if (port->null_scan) {
		free(port->null_scan);
		port->null_scan = NULL;
	}
	if (port->fin_scan) {
		free(port->fin_scan);
		port->fin_scan = NULL;
	}
	if (port->xmas_scan) {
		free(port->xmas_scan);
		port->xmas_scan = NULL;
	}
	if (port->ack_scan) {
		free(port->ack_scan);
		port->ack_scan = NULL;
	}
	if (port->udp_scan) {
		free(port->udp_scan);
		port->udp_scan = NULL;
	}
	if (port->tcp_scan) {
		free(port->tcp_scan);
		port->tcp_scan = NULL;
	}
}

static void	free_ports(struct s_port *ports)
{
	int i = 0;
	while (i < USHRT_MAX+1) {
		free_port(&ports[i]);
		i++;
	}
}

static int push_scan(struct s_port *scanlist, struct s_scan *new)
{
	struct s_scan **tmp;

	switch (new->scantype) {
		case OPT_SCAN_SYN:
			tmp = &scanlist->syn_scan;
			break;
		case OPT_SCAN_NULL:
			tmp = &scanlist->null_scan;
			break;
		case OPT_SCAN_FIN:
			tmp = &scanlist->fin_scan;
			break;
		case OPT_SCAN_XMAS:
			tmp = &scanlist->xmas_scan;
			break;
		case OPT_SCAN_ACK:
			tmp = &scanlist->ack_scan;
			break;
		case OPT_SCAN_UDP:
			tmp = &scanlist->udp_scan;
			break;
		case OPT_SCAN_TCP:
			tmp = &scanlist->tcp_scan;
			break;
		return 0;
	}

	*tmp = new;

	return 1;
}

int assign_port(uint16_t min, uint16_t max)
{
	static int start = -1;
	static int port = 0;

	if (start == -1) {
		start = ft_random(min, max);
		/* Verbose print */
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG ||
			g_data.opt & OPT_VERBOSE_PACKET)
		{
			fprintf(stderr, "[*] Starting scans from source port: %d\n",
				start);
		}
	}

	if (start == -1) {
		fprintf(stderr, "Port randomisation failed, setting start port to %d\n",
			min);
		start = min;
	}

	if (port < min || port >= max)
		port = start;
	else
		port++;

	return port;
}

static struct s_scan *create_scan(struct s_ip *ip, uint16_t port, int scantype)
{
	struct s_scan *tmp;

	tmp = (struct s_scan *)malloc(sizeof(struct s_scan));
	if (tmp) {
		ft_memset(tmp, 0, sizeof(struct s_scan));
		tmp->status = READY;
		tmp->dport = port;
		tmp->scantype = scantype;
		ft_memcpy(&tmp->saddr, ip->saddr, sizeof(struct sockaddr_in));
		/* Ephemeral Port Range, /proc/sys/net/ipv4/ip_local_port_range */
		if (scantype != OPT_SCAN_TCP) {
			tmp->sport = assign_port(g_data.port_min, g_data.port_max);
			tmp->saddr.sin_port = htons(tmp->sport);
		}

		ft_memcpy(&tmp->daddr, ip->daddr, sizeof(struct sockaddr_in));
		tmp->dhostname = ip->dhostname;
		tmp->daddr.sin_port = htons(tmp->dport);

		if (pthread_mutex_init(&tmp->lock, NULL) != 0)
			tmp->status = ERROR;
	}

	return tmp;
}

static int	push_scantypes(struct s_ip *ip, uint16_t port)
{
	int scans[] = {OPT_SCAN_SYN, OPT_SCAN_NULL, OPT_SCAN_FIN,
		OPT_SCAN_XMAS, OPT_SCAN_ACK, OPT_SCAN_UDP, OPT_SCAN_TCP, 0};
	int i = 0;
	struct s_scan *tmp;
	int ret = 0;

	struct s_port *ports = ip->ports;

	while (scans[i]) {
		if (g_data.opt & scans[i]) {
			tmp = create_scan(ip, port, scans[i]);
			if (tmp && !(push_scan(&ports[port], tmp))) {
				/* printf("[*] Scan %d on port %d already exists, dropping it\n",
					tmp->scantype, tmp->dport); */
				ret--;
				free(tmp);
			}
			else
				ret++;
		}
		i++;
	}
	return ret;
}

void	push_ports(struct s_ip **input, t_set *set)
{
	struct s_ip *ip = *input;
	size_t		crange, csingle;
	uint16_t	start, end;

	crange = 0;
	while (crange < set->nb_ranges) {
		start = set->ranges[crange].start;
		end = set->ranges[crange].end;
		while (start <= end) {
			if (push_scantypes(*input, start) > 0) {
				/* Verbose print */
				if (g_data.opt & OPT_VERBOSE_PACKET)
					fprintf(stderr, "[*] Filling structures for %s:%d\n",
						ip->dhostname, start);
				g_data.port_counter++;
			}
			if (start == USHRT_MAX)
				break;
			start++;
		}
		crange++;
	}
	csingle = 0;
	while (csingle < set->nb_single_values) {
		if (push_scantypes(*input, set->single_values[csingle]) > 0) {
			/* Verbose print */
			if (g_data.opt & OPT_VERBOSE_PACKET)
				fprintf(stderr, "[*] Filling structures for %s:%d\n",
					ip->dhostname, set->single_values[csingle]);
			g_data.port_counter++;
		}
		csingle++;
	}
}

void	push_ip(struct s_ip **head, struct s_ip *new)
{
	struct s_ip *tmp = *head;

	if (*head == NULL)
		*head = new;
	else {
		while (tmp->next != NULL)
			tmp = tmp->next;
		tmp->next = new;
	}
}

void	free_ips(struct s_ip **ip)
{
	struct s_ip *current = *ip;
	struct s_ip *next;

	while (current != NULL) {
		next = current->next;
		if (current->saddr)
			free(current->saddr);
		if (current->daddr)
			free(current->daddr);
		if (current->dhostname)
			free(current->dhostname);
		free_ports(current->ports);
		free(current);
		current = next;
	}
	*ip = NULL;
}
