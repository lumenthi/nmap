#include "nmap.h"
#include "options.h"

static uint64_t		get_time(void)
{
	struct timeval	time;

	if (gettimeofday(&time, NULL) == -1)
	{
		perror("gettimeofday");
		return 0;
	}
	return (time.tv_sec * 1000000 + time.tv_usec);
}

/* TODO use this for all tcp sends? */
static int send_tcp(int tcpsockfd,
	struct sockaddr_in *saddr, struct sockaddr_in *daddr, uint8_t flags)
{
	unsigned int len = 0;

	char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + len];
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

static int send_icmp(int icmpsockfd, struct sockaddr_in *saddr,
	struct sockaddr_in *daddr, uint8_t type, uint8_t code,
	uint16_t id, uint16_t sequence)
{
	unsigned int len = 0;
	if (type == ICMP_TIMESTAMP)
		len = 3 * sizeof(uint32_t);

	char packet[sizeof(struct iphdr) + sizeof(struct icmphdr) + len];
	struct iphdr *ip = (struct iphdr *)packet;

	ft_memset(packet, 0, sizeof(packet));
	craft_ip_packet(packet, saddr, daddr, IPPROTO_ICMP, NULL);
	craft_icmp_packet(packet, type, code, id, sequence, NULL, 0);

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[*] Sending ICMP request to: %s\n",
			inet_ntoa(daddr->sin_addr));

	if (g_data.opt & OPT_VERBOSE_DEBUG)
		print_ip4_header((struct ip *)ip);

	/* Sending handcrafted packet */
	if (sendto(icmpsockfd, packet, sizeof(packet), 0, (struct sockaddr *)daddr,
		sizeof(struct sockaddr)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[*] Failed to send ICMP packet to: %s\n",
			inet_ntoa(daddr->sin_addr));
		return 1;
	}

	return 0;
}

int	receive_icmp(int icmpsock, uint16_t echo_id, uint16_t timestamp_id)
{
	unsigned int len =
		sizeof(struct ip) + sizeof(struct icmp) + 3 * sizeof(uint32_t);
	char icmpbuffer[len];
	int	recv_icmp = 0;
	ssize_t ret;
	while (recv_icmp < 2) {
		ret = recv(icmpsock, icmpbuffer, len, 0);
		if (ret < (ssize_t)(sizeof(struct ip) + sizeof(struct icmphdr)))
			continue ;
		struct iphdr *ip = (struct iphdr*)icmpbuffer;
		struct icmphdr *icmp = (struct icmphdr*)(ip + 1); 
		if (icmp->type == ICMP_ECHOREPLY && icmp->un.echo.id == echo_id) {
			printf("ECHO REPLY!!\n");
			recv_icmp++;
		}
		else if (icmp->type == ICMP_TIMESTAMPREPLY
			&& icmp->un.echo.id == timestamp_id) {
			printf("TIMESTAMP REPLY!!\n");
			recv_icmp++;
		}
	}
	return 0;
}

int	discover_target(struct s_ip *ip)
{
	int tcpsock, icmpsock;
	struct timeval start_time, end_time;
	struct sockaddr_in tcp443, tcp80, icmp, source;
	uint16_t echo_id, timestamp_id;

	/* Socket creation */
	/* TODO set timeout */
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
	/* TODO set timeout */
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
	if (sconfig(inet_ntoa(source.sin_addr), &source) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[*] Failed to config source address for host discovery\n");
		return 1;
	}
	source.sin_port = htons(assign_port(g_data.port_min, g_data.port_max));

	tcp443.sin_family = AF_INET;
	tcp443.sin_addr.s_addr = ip->daddr->sin_addr.s_addr;
	tcp443.sin_port = htons(443);

	tcp80.sin_family = AF_INET;
	tcp80.sin_addr.s_addr = ip->daddr->sin_addr.s_addr;
	tcp80.sin_port = htons(80);

	icmp.sin_family = AF_INET;
	icmp.sin_addr.s_addr = ip->daddr->sin_addr.s_addr;

	/* TODO: Connect scan if unprivileged */
	if (send_tcp(tcpsock, &source, &tcp443, TH_SYN)) {
	}

	if (send_tcp(tcpsock, &source, &tcp80, TH_ACK)) {
	}

	/* Scan start time */
	if ((gettimeofday(&start_time, NULL)) != 0) {
	}

	echo_id = get_time();
	if (send_icmp(icmpsock, &source, &icmp, ICMP_ECHO, 0, echo_id, 0)) {
	}

	timestamp_id = get_time();
	if (send_icmp(icmpsock, &source, &icmp, ICMP_TIMESTAMP, 0, timestamp_id, 0)) {
	}

	receive_icmp(icmpsock, echo_id, timestamp_id);
	read_syn_ack(tcpsock, icmpsock, NULL, timeout);

	/* Scan end time */
	if ((gettimeofday(&end_time, NULL)) != 0) {
	}

	close(tcpsock);
	close(icmpsock);
	
	return 0;
}

int		host_discovery(void)
{
	struct s_ip *ip = g_data.ips;

	while (ip) {
		discover_target(ip);
		ip = ip->next;
	}
	return 0;
}
