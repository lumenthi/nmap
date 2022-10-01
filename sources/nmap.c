#include "nmap.h"
#include "options.h"

static void assign_ports(uint16_t *port_min, uint16_t *port_max)
{
	int device_size = 11;
	int fd;
	char data[device_size];
	int i = 0;

	*port_min = DEFAULT_EPHEMERAL_MIN;
	*port_max = DEFAULT_EPHEMERAL_MAX;

	fd = open("/proc/sys/net/ipv4/ip_local_port_range", O_RDONLY);
	if (fd < 0)
		return;

	device_size = read(fd, data, device_size);
	*port_min = 0;
	/* Read min */
	while (ft_isdigit(data[i]) && i < device_size) {
		if (ft_isdigit(data[i]))
			*port_min = *port_min * 10 + (data[i] - '0');
		i++;
	}
	*port_max = 0;
	/* Read max */
	while (i < device_size) {
		if (ft_isdigit(data[i]))
			*port_max = *port_max * 10 + (data[i] - '0');
		i++;
	}

	/* printf("Port min: %d, Port max: %d\n", *port_min, *port_max); */

	close(fd);
}

int run_scan(struct s_scan *scan)
{
	if (scan->scantype == OPT_SCAN_SYN)
		syn_scan(scan);
	else
		printf("[*] Scan %d not implemented yet\n",
			scan->scantype);

	return 0;
}

int ft_nmap(char *path)
{
	struct s_ip *ip = g_data.ips;
	struct s_scan *scan;
	uint16_t port_min;
	uint16_t port_max;

	if (getuid() != 0) {
		fprintf(stderr, "%s: Not allowed to create raw sockets, run as root\n",
			path);
		return 1;
	}

	assign_ports(&port_min, &port_max);

	if (port_min > port_max) {
		fprintf(stderr, "%s: Source ports configuration error\n",
			path);
		return 1;
	}

	while (ip) {
		scan = ip->scans;
		/* Default status */
		ip->status = UP;
		/* Prepare addr structs */
		ip->saddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		ip->daddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		if (!ip->saddr || !ip->daddr)
			ip->status = ERROR;
		if (dconfig(ip->destination, 0, ip->daddr, &ip->dhostname) != 0)
			ip->status = DOWN;
		if (sconfig(inet_ntoa(ip->daddr->sin_addr), ip->saddr) != 0)
			ip->status = ERROR;

		/* Resolve scans for this IP */
		while (ip->status == UP && scan) {
			scan->status = READY;

			scan->saddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
			if (!scan->saddr)
				scan->status = ERROR;
			else {
				ft_memcpy(scan->saddr, ip->saddr, sizeof(struct sockaddr_in));
				/* Ephemeral Port Range, /proc/sys/net/ipv4/ip_local_port_range */
				scan->sport = ft_random(port_min, port_max);
			}

			scan->daddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
			if (!scan->daddr)
				scan->status = ERROR;
			else {
				ft_memcpy(scan->daddr, ip->daddr, sizeof(struct sockaddr_in));
				scan->dhostname = ip->dhostname;
			}

			if (scan->status == READY)
				run_scan(scan);
			scan = scan->next;
		}
		ip = ip->next;
	}

	print_scans(g_data.ips);
	return 0;
}
