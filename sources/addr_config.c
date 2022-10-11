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

/* Fill source sockaddr_in */
int sconfig(char *destination, struct sockaddr_in *saddr,
	struct sockaddr_ll *sethe)
{
	/* Interface name */
	char iname[IFNAMSIZ];

	ft_bzero(iname, sizeof(iname));

	if (get_ip(destination, saddr, iname) != 0)
		return 1;

	/*printf("iname: %s\n", iname);*/

	if (get_mac(iname, sethe) != 0)
		return 1;

	/*unsigned char *display = (unsigned char *)sethe.sll_addr;
	printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	display[0],
	display[1],
	display[2],
	display[3],
	display[4],
	display[5]);*/

	return 0;
}
