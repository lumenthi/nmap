#include "nmap.h"
#include "options.h"
#include "colors.h"
#include <math.h>

#define BAR_SIZE 70
#define R 0
#define G 1
#define B 2

void	print_progress()
{
	pthread_mutex_lock(&g_data.print_lock);
	g_data.finished_scans++;
	float progress = 100.0f * g_data.finished_scans / (float)g_data.total_scan_counter;
	printf("\r|");

	/* ASCII */
	/*for (int_fast32_t i = 0; i < floor(progress / 2); i++)
		printf("|");
	for (int_fast32_t i = 0; i < 50 - floor(progress / 2); i++)
		printf("-");*/

	int start[3] = {0xbd, 0xc3, 0xc7};
	int end[3] = {0x2c, 0x3e, 0x50};
	(void)start;
	(void)end;
	/* GREEN GRADIANT */
	/*for (int_fast32_t i = 0; i < floor(progress / 2); i++) {
		printf("\e[48;2;%d;%d;%dm ",
			(int)(i / 25.0f * 255),
			(int)(i / 25.0f * 255) + 64,
			(int)(i / 25.0f * 255) 
			);
	}*/
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

	/* GREEN GRADIANT 2 */
	/*for (int_fast32_t i = 0; i < 50; i++) {
		printf("\e[48;2;%d;%d;%dm ", 0,(int)(progress / 100.0f * 255), 0);
	}
	printf(NMAP_COLOR_RESET);*/

	printf("| %.2f%%", progress);
	fflush(stdout);
	pthread_mutex_unlock(&g_data.print_lock);
}

/* Update scan with port `source_port`
 * returns UPDATE_TARGET if our target scan `scan` is updated
 * returns UPDATE if we update another scan than target scan `scan` */
int update_scans(struct s_scan *scan, int status, uint16_t source_port,
	uint16_t dest_port, int scantype)
{
	struct s_scan *tmp = scan;
	while (tmp) {
		if ((tmp->status == SCANNING || tmp->status == TIMEOUT) &&
			tmp->saddr.sin_port == source_port &&
			tmp->daddr.sin_port == dest_port && tmp->scantype == scantype)
		{
			LOCK(tmp);
			tmp->status = status;
			//if (!(g_data.opt & OPT_NO_PROGRESS))
			//	print_progress();
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
	//if (current->saddr)
	//	free(current->saddr);

	//if (current->daddr)
	//	free(current->daddr);

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

	if (port < min || port >= max)
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
		tmp->final_status = -1;
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
		while (start <= end) {
			if (push_scantypes(*input, &ip->scans, start++) > 0)
				g_data.port_counter++;
		}
		crange++;
	}
	csingle = 0;
	while (csingle < set->nb_single_values) {
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
