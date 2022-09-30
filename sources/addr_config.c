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

	*hostname = ft_strdup(host->h_name);

	return 0;
}

/* Fill source sockaddr_in */
int sconfig(char *destination, struct sockaddr_in *saddr)
{
	struct ifaddrs *addrs;
	struct ifaddrs *tmp;

	ft_memset(saddr, 0, sizeof(*saddr));

	saddr->sin_family = AF_INET;
	saddr->sin_port = 0;

	if (!ft_strcmp(destination, "127.0.0.1")) {
		if (inet_pton(AF_INET, "127.0.0.1", &(saddr->sin_addr)) != 1)
			return 1;
		return 0;
	}
	else {
		if (getifaddrs(&addrs) != 0)
			return 1;
		tmp = addrs;
		while (tmp)
		{
			if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
			{
				struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
				/* printf("%s: %s\n", tmp->ifa_name, inet_ntoa(pAddr->sin_addr)); */
				if (!(tmp->ifa_flags & IFF_LOOPBACK)) {
					if (inet_pton(AF_INET, inet_ntoa(pAddr->sin_addr), &(saddr->sin_addr)) != 1) {
						freeifaddrs(addrs);
						return 1;
					}
					else {
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
