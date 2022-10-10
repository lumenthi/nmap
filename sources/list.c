#include "nmap.h"
#include "options.h"

/* Update scan with port `source_port`
 * returns UPDATE_TARGET if our target scan `scan` is updated
 * returns UPDATE if we update another scan than target scan `scan` */
int update_scans(struct s_scan *scan, int status, uint16_t source_port)
{
	struct s_scan *tmp = scan;

	while (tmp) {
		if ((tmp->status == SCANNING || tmp->status == TIMEOUT) &&
			tmp->saddr->sin_port == source_port)
		{
			LOCK(tmp);
			tmp->status = status;
			if (tmp == scan) {
				UNLOCK(tmp);
				return UPDATE_TARGET;
			}
			UNLOCK(tmp);
			return UPDATE;
		}
		tmp = tmp->next;
	}
	return 0;
}

static void	free_scan(struct s_scan *current)
{
	if (current->saddr)
		free(current->saddr);

	if (current->daddr)
		free(current->daddr);

	if (current->service)
		free(current->service);

	free(current);
}

static void	free_scans(struct s_scan **scan)
{
	struct s_scan *current = *scan;
	struct s_scan *next;

	while (current != NULL) {
		next = current->next;
		free_scan(current);
		current = next;
	}
	*scan = NULL;
}

static int push_scan(struct s_scan **head, struct s_scan *new)
{
	struct s_scan *tmp = *head;

	if (*head == NULL || (tmp->dport >= new->dport &&
		tmp->scantype == new->scantype)) {
		if (tmp && (tmp->dport == new->dport))
			return 0;
		new->next = *head;
		*head = new;
	}
	else {
		while (tmp->next != NULL &&
			new->dport >= tmp->next->dport) {
				if (tmp->next->dport == new->dport &&
					tmp->next->scantype == new->scantype)
					return 0;
				tmp = tmp->next;
		}
		new->next = tmp->next;
		tmp->next = new;
	}
	return 1;
}

static int assign_port(uint16_t min, uint16_t max)
{
	static int port = 0;

	if (port < min || port > max)
		port = min;
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
		tmp->saddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		if (!tmp->saddr)
			tmp->status = ERROR;
		else {
			ft_memcpy(tmp->saddr, ip->saddr, sizeof(struct sockaddr_in));
			/* Ephemeral Port Range, /proc/sys/net/ipv4/ip_local_port_range */
			tmp->sport = assign_port(g_data.port_min, g_data.port_max);
		}

		tmp->daddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		if (!tmp->daddr)
			tmp->status = ERROR;
		else {
			ft_memcpy(tmp->daddr, ip->daddr, sizeof(struct sockaddr_in));
			tmp->dhostname = ip->dhostname;
		}
		tmp->dport = port;
		tmp->scantype = scantype;

		if (pthread_mutex_init(&tmp->lock, NULL) != 0)
			tmp->status = ERROR;

	}

	return tmp;
}

static int	push_scantypes(struct s_ip *ip, struct s_scan **head, uint16_t port)
{
	int scans[] = {OPT_SCAN_SYN, OPT_SCAN_NULL, OPT_SCAN_FIN,
		OPT_SCAN_XMAS, OPT_SCAN_ACK, OPT_SCAN_UDP, OPT_SCAN_TCP, 0};
	int i = 0;
	struct s_scan *tmp;
	int ret = 0;

	while (scans[i]) {
		if (g_data.opt & scans[i]) {
			tmp = create_scan(ip, port, scans[i]);
			if (tmp && !(push_scan(head, tmp))) {
				/* printf("[*] Scan %d on port %d already exists, dropping it\n",
					tmp->scantype, tmp->dport); */
				ret--;
				free_scan(tmp);
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
		//printf("Adding range of ports [%d - %d]\n",	start, end);
		while (start <= end)
		{
			//printf("\tAdding ip %s port %d \n",
			//	inet_ntoa(ip->daddr->sin_addr), start);
			if (push_scantypes(*input, &ip->scans, start++) > 0) {
			/* I use this to keep a track of the number of ports to scan */
				g_data.port_counter++;
			}
		}
		crange++;
	}
	csingle = 0;
	while (csingle < set->nb_single_values) {
		//printf("%ld Adding ip %s port %d \n", csingle,
		//	inet_ntoa(ip->daddr->sin_addr), set->single_values[csingle]);
		if (push_scantypes(*input, &ip->scans, set->single_values[csingle]) > 0)
			g_data.port_counter++;
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
		free_scans(&current->scans);
		free(current);
		current = next;
	}
	*ip = NULL;
}
