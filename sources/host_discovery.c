#include "nmap.h"
#include "options.h"

/* TODO used this for all tcp sends? */
static int send_tcp(int tcpsockfd,
	struct sockaddr_in *saddr, struct sockaddr_in *daddr, uint8_t flags)
{
	unsigned int len = 0;

	char packet[sizeof(struct iphdr)+sizeof(struct tcphdr)+len];
	struct iphdr *ip = (struct iphdr *)packet;

	ft_memset(packet, 0, sizeof(packet));
	craft_ip_packet(packet, saddr, daddr, IPPROTO_TCP, NULL);
	craft_tcp_packet(packet, saddr, daddr, flags, NULL);

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Sending TCP request to: %s:%d from port %d\n",
			inet_ntoa(daddr->sin_addr), ntohs(daddr->sin_port),
			ntohs(saddr->sin_port));

	if (g_data.opt & OPT_VERBOSE_DEBUG)
		print_ip4_header((struct ip *)ip);

	/* Sending handcrafted packet */
	if (sendto(tcpsockfd, packet, sizeof(packet), 0, (struct sockaddr *)daddr,
		sizeof(struct sockaddr)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[*] Failed to send TCP packet to: %s:%d from port %d\n",
			inet_ntoa(daddr->sin_addr), ntohs(daddr->sin_port),
			ntohs(saddr->sin_port));
		return 1;
	}

	return 0;
}

int	discover_target(struct s_ip *ip)
{
	int tcpsock, icmpsock;
	struct timeval start_time, end_time;
	struct sockaddr_in tcp443, tcp80, icmp, source;

	/* Socket creation */
	if ((tcpsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[*] Failed to create socket\n");
		return 1;
	}
	/* Set options */
	int one = 1;
	if ((setsockopt(tcpsock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[*] Failed to set header option\n");
		close(tcpsock);
		return 1;
	}

	/* ICMP Socket creation */
	if ((icmpsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[*] Failed to create ICMP socket\n");
		close(tcpsock);
		close(icmpsock);
		return 1;
	}
	/* Set options */
	if ((setsockopt(icmpsock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[*] Failed to set header option\n");
		close(tcpsock);
		close(icmpsock);
		return 1;
	}

	source.sin_family = AF_INET;
	source.sin_addr.s_addr = ip->saddr->sin_addr.s_addr;
	source.sin_port = htons(assign_port(g_data.port_min, g_data.port_max));
	if (sconfig(inet_ntoa(source.sin_addr), &source) != 0) {
	}

	tcp443.sin_family = AF_INET;
	tcp443.sin_addr.s_addr = ip->saddr->sin_addr.s_addr;
	tcp443.sin_port = htons(443);

	tcp80.sin_family = AF_INET;
	tcp80.sin_addr.s_addr = ip->saddr->sin_addr.s_addr;
	tcp80.sin_port = htons(80);

	icmp.sin_family = AF_INET;
	icmp.sin_addr.s_addr = ip->saddr->sin_addr.s_addr;

	if (send_tcp(tcpsock, &source, &tcp443, TH_SYN)) {
	}

	if (send_tcp(tcpsock, &source, &tcp80, TH_ACK)) {
	}

	/* TODO ICMP send */
	(void)icmp;
	//if (send_icmp(icmpsock, &source, &icmp)) {
	//}

	/* Scan start time */
	if ((gettimeofday(&start_time, NULL)) != 0) {
	}
	/* Scan end time */
	if ((gettimeofday(&end_time, NULL)) != 0) {
	}

	(void)ip;

	close(tcpsock);
	close(icmpsock);
	
	return 0;
}

int		host_discovery(void)
{
	struct s_ip *ip = g_data.ips;

	while (ip) {
		if (ip->status == UP)
			discover_target(ip);
		ip = ip->next;
	}
	return 0;
}
