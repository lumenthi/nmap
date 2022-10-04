#include "nmap.h"
#include "options.h"

static void push_scan(struct s_scan **head, struct s_scan *new)
{
	struct s_scan *tmp = *head;

	if (*head == NULL)
		*head = new;
	else {
		while (tmp->next != NULL)
			tmp = tmp->next;
		tmp->next = new;
	}
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
			tmp->sport = ft_random(g_data.port_min, g_data.port_max);
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
	}

	return tmp;
}

static void	push_scantype(struct s_ip *ip, struct s_scan **head, uint16_t port)
{
	int scans[] = {OPT_SCAN_SYN, OPT_SCAN_NULL, OPT_SCAN_FIN,
		OPT_SCAN_XMAS, OPT_SCAN_ACK, OPT_SCAN_UDP, OPT_SCAN_TCP, 0};
	int i = 0;
	struct s_scan *tmp;

	while (scans[i]) {
		if (g_data.opt & scans[i]) {
			tmp = create_scan(ip, port, scans[i]);
			if (tmp)
				push_scan(head, tmp);
		}
		i++;
	}
}

void	push_ports(struct s_ip **input, uint16_t start, uint16_t end)
{
	struct s_ip *ip = *input;

	while (start <= end) {
		push_scantype(*input, &ip->scans, start++);
		g_data.port_counter++;
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

void	free_scans(struct s_scan **scan)
{
	struct s_scan *current = *scan;
	struct s_scan *next;

	while (current != NULL) {
		next = current->next;

		if (current->saddr)
			free(current->saddr);

		if (current->daddr)
			free(current->daddr);

		if (current->service)
			free(current->service);

		free(current);
		current = next;
	}
	*scan = NULL;
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
