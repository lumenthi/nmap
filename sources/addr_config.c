#include "nmap.h"

/* Fill destination sockaddr_in */
int dconfig(char *destination, uint16_t port, struct sockaddr_in *daddr,
	char **hostname)
{
	struct hostent *host;

	ft_memset(daddr, 0, sizeof(*daddr));
	if (!(host = gethostbyname(destination)))
		return 1;

	daddr->sin_family = host->h_addrtype;
	daddr->sin_port = htons(port);
	ft_memcpy(&(daddr->sin_addr.s_addr), host->h_addr_list[0], host->h_length);

	if (hostname)
		*hostname = ft_strdup(host->h_name);

	return 0;
}

static int get_mac(char *iname, struct sockaddr_ll *macaddr)
{
	struct ifaddrs *addrs;
	struct ifaddrs *tmp;

	if (getifaddrs(&addrs) != 0)
		return 1;

	tmp = addrs;
	while (tmp)
	{
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
		{
			if (!ft_strcmp(tmp->ifa_name, iname)) {
				ft_memcpy(macaddr, (struct sockaddr_ll *)tmp->ifa_addr, sizeof(struct sockaddr_ll));
				freeifaddrs(addrs);
				return 0;
			}
		}
		tmp = tmp->ifa_next;
	}
	freeifaddrs(addrs);
	return 1;
}

static int get_ip(char *destination, struct sockaddr_in *saddr, char *iname)
{
	struct ifaddrs *addrs;
	struct ifaddrs *tmp;

	ft_memset(saddr, 0, sizeof(*saddr));

	saddr->sin_family = AF_INET;
	saddr->sin_port = 0;

	if (!ft_strcmp(destination, "127.0.0.1")) {
		if (inet_pton(AF_INET, destination, &(saddr->sin_addr)) != 1)
			return 1;
		ft_strncpy(iname, "lo", IFNAMSIZ);
		return 0;
	}
	else {
		if (getifaddrs(&addrs) != 0)
			return 1;
		tmp = addrs;
		while (tmp)
		{
			/*struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
			printf("%s: %s\n", tmp->ifa_name, inet_ntoa(pAddr->sin_addr));*/
			if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
			{
				struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
				if (!(tmp->ifa_flags & IFF_LOOPBACK)) {
					if (inet_pton(AF_INET, inet_ntoa(pAddr->sin_addr), &(saddr->sin_addr)) != 1) {
						freeifaddrs(addrs);
						return 1;
					}
					else {
						ft_strncpy(iname, tmp->ifa_name, IFNAMSIZ);
						freeifaddrs(addrs);
						return 0;
					}
				}
			}
			tmp = tmp->ifa_next;
		}
		freeifaddrs(addrs);
	}
	return 1;
}

static void free_split(char **split)
{
	char **tmp = split;

	while (*tmp) {
		free(*tmp);
		tmp++;
	}
	free(split);
}

static void mac_value(char *str, char *sll_addr)
{
	int i = 0;

	while (i < ETHER_ADDR_LEN) {
		str[2] = '\0';
		sll_addr[i] = ft_atoi_base(str, "0123456789abcdef");
		str+=3;
		i++;
	}
}

static size_t split_size(char **split)
{
	int i = 0;

	if (!split)
		return 0;

	while (split[i])
		i++;

	return i;
}

static int get_arp(char *iname, struct sockaddr_ll *macaddr)
{
	char **split;
	char *buffer;
	int i = 0;
	int found = 1;

	if (!ft_strcmp(iname, "lo")) {
		ft_bzero(macaddr->sll_addr, sizeof(*macaddr->sll_addr));
		return 0;
	}

	int fd = open("/proc/net/arp", O_RDONLY);
	if (fd == -1)
		return 1;

	while (get_next_line(fd, &buffer)) {
		split = ft_strsplit(buffer, ' ');
		if (split_size(split) > 5 && split[5] && !ft_strcmp(split[5], iname) &&
			split[3] && ft_strlen(split[3]) == 17)
		{
			mac_value(split[3], (char *)macaddr->sll_addr);
			found = 0;
		}
		free_split(split);
		free(buffer);
		i++;
	}

	return found;
}

/* Fill source sockaddr_in */
int sconfig(char *destination, struct sockaddr_in *saddr,
	struct sockaddr_ll *sethe, struct sockaddr_ll *dethe)
{
	/* Interface name */
	char iname[IFNAMSIZ];

	ft_bzero(iname, sizeof(iname));

	if (get_ip(destination, saddr, iname) != 0)
		return 1;

	/*printf("iname: %s\n", iname);*/

	if (get_mac(iname, sethe) != 0)
		return 1;

	if (get_arp(iname, dethe) != 0)
		return 1;

	/*unsigned char *sdisplay = (unsigned char *)sethe->sll_addr;
	printf("SETHE: %02x:%02x:%02x:%02x:%02x:%02x\n",
	sdisplay[0],
	sdisplay[1],
	sdisplay[2],
	sdisplay[3],
	sdisplay[4],
	sdisplay[5]);

	unsigned char *ddisplay = (unsigned char *)dethe->sll_addr;
	printf("DETHE: %02x:%02x:%02x:%02x:%02x:%02x\n",
	ddisplay[0],
	ddisplay[1],
	ddisplay[2],
	ddisplay[3],
	ddisplay[4],
	ddisplay[5]);*/

	return 0;
}
