#include "nmap.h"
#include "options.h"

void push_scan(struct s_scan **head, struct s_scan *new)
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

static struct s_scan *create_scan(uint16_t port, int scantype)
{
	struct s_scan *tmp;

	tmp = (struct s_scan *)malloc(sizeof(struct s_scan));
	if (tmp) {
		ft_memset(tmp, 0, sizeof(struct s_scan));
		tmp->dport = port;
		tmp->scantype = scantype;
	}

	return tmp;
}

void	push_ports(struct s_ip **input, uint16_t start, uint16_t end)
{
	struct s_ip *ip = *input;
	struct s_scan *tmp;

	while (start <= end) {
		if (g_data.opt & OPT_SCAN_SYN) {
			tmp = create_scan(start, OPT_SCAN_SYN);
			if (tmp)
				push_scan(&ip->scans, tmp);
		}
		if (g_data.opt & OPT_SCAN_NULL) {
			tmp = create_scan(start, OPT_SCAN_NULL);
			if (tmp)
				push_scan(&ip->scans, tmp);
		}
		if (g_data.opt & OPT_SCAN_FIN) {
			tmp = create_scan(start, OPT_SCAN_FIN);
			if (tmp)
				push_scan(&ip->scans, tmp);
		}
		start++;
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
