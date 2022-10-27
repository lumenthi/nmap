#include "nmap.h"
#include "options.h"
#include "libft.h"

struct s_timeout_data {
	uint64_t	start[4];
	uint64_t	end[4];
	int			nb_recv;
};

void	update_timeout(struct s_ip *ip, uint64_t start, uint64_t end)
{
	int64_t oldsrtt = ip->srtt;
	int64_t instanceRtt = end - start;
	//printf("Current rtt = %ldus (%fms)\n", instanceRtt, instanceRtt / 1000.0);
	//printf("current srtt = %ldus (%fms)\n", oldsrtt, oldsrtt / 1000.0);
	//printf("diff = %ldus (%fms)\n", instanceRtt - oldsrtt, (instanceRtt - oldsrtt) / 1000.0);
	ip->srtt = oldsrtt + (instanceRtt - oldsrtt) / 8.0;
	//printf("srtt = %ldus (%fms)\n", ip->srtt, ip->srtt / 1000.0);
	//printf("current rttvar = %ld.%06ld\n", ip->rttvar / 1000000, ip->rttvar % 1000000);
	ip->rttvar = ip->rttvar + (ft_llabs(instanceRtt - oldsrtt) - ip->rttvar) / 4.0;
	//printf("New rttvar = %ld (%fms)\n", ip->rttvar , ip->rttvar / 1000.0);
	ip->timeout = ip->srtt + ip->rttvar * 4;
	//printf("New timeout = %ldus (%fms)\n", ip->timeout, ip->timeout / 1000.0);
}

static int send_tcp(int tcpsockfd, struct s_ip *ip,
	struct sockaddr_in *saddr, struct sockaddr_in *daddr, uint8_t flags)
{
	uint64_t start, end;
	unsigned int len =
		sizeof(struct ip) + sizeof(struct tcphdr);

	char packet[len];
	struct iphdr *iphdr = (struct iphdr *)packet;

	ft_memset(packet, 0, sizeof(packet));
	craft_ip_packet(packet, saddr, daddr, IPPROTO_TCP, NULL);
	craft_tcp_packet(packet, saddr, daddr, flags, NULL);

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG)
		fprintf(stderr, "[***] Sending TCP request to: %s:%d from port %d\n",
			inet_ntoa(daddr->sin_addr), ntohs(daddr->sin_port),
			ntohs(saddr->sin_port));

	if (g_data.opt & OPT_VERBOSE_PACKET)
		print_ip4_header((struct ip *)iphdr);

	/* Sending handcrafted packet */
	start = get_time();
	if (sendto(tcpsockfd, packet, sizeof(packet), 0, (struct sockaddr *)daddr,
		sizeof(struct sockaddr)) < 0) {
		if (g_data.opt & OPT_VERBOSE_PACKET || g_data.opt & OPT_VERBOSE_DEBUG)
			fprintf(stderr, "[***] Failed to send TCP packet to: %s:%d from port %d\n",
			inet_ntoa(daddr->sin_addr), ntohs(daddr->sin_port),
			ntohs(saddr->sin_port));
		return 0;
	}

	char tcpbuffer[len];
	ssize_t ret;
	int64_t	diff = 0;

	while (diff < 1000000) {
		ret = recv(tcpsockfd, tcpbuffer, len, 0);
		end = get_time();
		diff = end - start;
		if (ret == -1)
			return 0;
		if (ret < (ssize_t)(sizeof(struct ip) + sizeof(struct tcphdr)))
			return 0;
		iphdr = (struct iphdr*)tcpbuffer;
		struct tcphdr *tcp = (struct tcphdr*)(iphdr + 1); 
		if (tcp->dest == saddr->sin_port && (tcp->source == ntohs(443)
			|| tcp->source == ntohs(80))) {
			/* TODO: if there was a given initial timeout, don't do this */
			if (g_data.opt & OPT_VERBOSE_DEBUG || g_data.opt & OPT_VERBOSE_PACKET)
				fprintf(stderr, "[***] Received TCP from port %d\n",
				ntohs(tcp->source));
			if (g_data.opt & OPT_VERBOSE_PACKET)
				print_ip4_header((struct ip*)iphdr);
			if (ip->srtt == 0) {
				ip->srtt = diff;
				ip->timeout = ip->srtt * 3;
			}
			else
				update_timeout(ip, start, end);
			return 1;
		}
	}
	return 0;
}

static int send_icmp(int icmpsockfd, struct s_ip *ip, struct sockaddr_in *saddr,
	struct sockaddr_in *daddr, uint8_t type, uint8_t code,
	uint16_t id, uint16_t sequence)
{
	uint64_t start, end;
	unsigned int len = 0;
	if (type == ICMP_TIMESTAMP)
		len = 3 * sizeof(uint32_t);

	char packet[sizeof(struct iphdr) + sizeof(struct icmphdr) + len];
	struct iphdr *iphdr = (struct iphdr *)packet;

	ft_memset(packet, 0, sizeof(packet));
	craft_ip_packet(packet, saddr, daddr, IPPROTO_ICMP, NULL);
	craft_icmp_packet(packet, type, code, id, sequence, NULL, 0);

	/* Verbose print */
	if (g_data.opt & OPT_VERBOSE_DEBUG || g_data.opt & OPT_VERBOSE_PACKET)
		fprintf(stderr, "[***] Sending ICMP type %d with id %d to: %s\n",
			type, id, inet_ntoa(daddr->sin_addr));

	if (g_data.opt & OPT_VERBOSE_PACKET)
		print_ip4_header((struct ip *)iphdr);

	/* Sending handcrafted packet */
	start = get_time();
	if (sendto(icmpsockfd, packet, sizeof(packet), 0, (struct sockaddr *)daddr,
		sizeof(struct sockaddr)) < 0) {
		if (g_data.opt & OPT_VERBOSE_DEBUG || g_data.opt & OPT_VERBOSE_PACKET)
			fprintf(stderr, "[***] Failed to send ICMP packet to: %s\n",
			inet_ntoa(daddr->sin_addr));
		return 0;
	}

	unsigned int len2 =
		sizeof(struct ip) + sizeof(struct icmp) + 3 * sizeof(uint32_t);
	char icmpbuffer[len2];
	ssize_t ret;
	int64_t	diff = 0;

	while (diff < 1000000) {
		ret = recv(icmpsockfd, icmpbuffer, len2, 0);
		end = get_time();
		diff = end - start;
		if (ret == -1)
			return 0;
		if (ret < (ssize_t)(sizeof(struct ip) + sizeof(struct icmphdr)))
			return 0;
		iphdr = (struct iphdr*)icmpbuffer;
		struct icmphdr *icmp = (struct icmphdr*)(iphdr + 1); 
		if (((type == ICMP_ECHO && icmp->type == ICMP_ECHOREPLY)
			|| (type == ICMP_TIMESTAMP && icmp->type == ICMP_TIMESTAMPREPLY))
			&& icmp->un.echo.id == id) {
			if (g_data.opt & OPT_VERBOSE_DEBUG || g_data.opt & OPT_VERBOSE_PACKET)
				fprintf(stderr, "[***] Received ICMP type %d code %d\n",
				icmp->type, icmp->code);
			if (g_data.opt & OPT_VERBOSE_PACKET)
				print_ip4_header((struct ip*)iphdr);
			update_timeout(ip, start, end);
			return 1;
		}
	}
	return 0;
}

int	discover_target(struct s_ip *ip)
{
	int tcpsock, icmpsock;
	int one = 1, ret = 0;
	struct timeval timeout = {1, 0};
	struct sockaddr_in tcp443, tcp80, icmp, source;
	uint16_t echo_id, timestamp_id;

	/* Socket creation */
	if ((tcpsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET)
			fprintf(stderr, "[**] Failed to create socket\n");
		return 1;
	}
	/* Set options */
	if ((setsockopt(tcpsock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET)
			fprintf(stderr, "[**] Failed to set header option\n");
		close(tcpsock);
		return 1;
	}
	if (setsockopt(tcpsock, SOL_SOCKET, SO_RCVTIMEO,
		&timeout, sizeof(timeout)) != 0)
	{
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET)
			fprintf(stderr, "[**] Failed to set header option\n");
		close(tcpsock);
		return 1;
	}

	/* ICMP Socket creation */
	if ((icmpsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET)
			fprintf(stderr, "[**] Failed to create ICMP socket\n");
		close(tcpsock);
		close(icmpsock);
		return 1;
	}
	/* Set options */
	if ((setsockopt(icmpsock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET)
			fprintf(stderr, "[**] Failed to set header option\n");
		close(tcpsock);
		close(icmpsock);
		return 1;
	}
	if (setsockopt(icmpsock, SOL_SOCKET, SO_RCVTIMEO,
		&timeout, sizeof(timeout)) != 0)
	{
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET)
			fprintf(stderr, "[**] Failed to set header option\n");
		close(tcpsock);
		close(icmpsock);
		return 1;
	}

	source.sin_family = AF_INET;
	source.sin_addr.s_addr = ip->saddr->sin_addr.s_addr;
	if (sconfig(inet_ntoa(source.sin_addr), &source) != 0) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET)
			fprintf(stderr, "[**] Failed to config source address for host discovery\n");
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
	icmp.sin_port = 0;

	/* Idea: Connect scan if unprivileged */
	ret += send_tcp(tcpsock, ip, &source, &tcp443, TH_SYN);

	ret += send_tcp(tcpsock, ip, &source, &tcp80, TH_ACK);

	echo_id = get_time();
	ret += send_icmp(icmpsock, ip, &source, &icmp, ICMP_ECHO, 0, echo_id, 0);

	timestamp_id = get_time();
	ret += send_icmp(icmpsock, ip, &source, &icmp, ICMP_TIMESTAMP, 0, timestamp_id, 0);

	if (!ret) {
		ip->status = DOWN;
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
				|| g_data.opt & OPT_VERBOSE_PACKET)
			fprintf(stderr, "[***] Host %s is down\n", ip->dhostname);
	}
	else if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET) {
		fprintf(stderr, "[***] Host %s is up\n", ip->dhostname);
	}

	if (g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET)
		fprintf(stderr, "[***] %s initial timeout set to be %ld.%06ld\n",
			ip->dhostname, ip->timeout / 1000000, ip->timeout % 1000000);

	close(tcpsock);
	close(icmpsock);
	
	return 0;
}

int		host_discovery(void)
{
	struct s_ip *ip = g_data.ips;

	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET)
		fprintf(stderr, "[*] Starting host discovery\n");

	while (ip) {
		if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
				|| g_data.opt & OPT_VERBOSE_PACKET)
			fprintf(stderr, "[**] Scanning %s\n", ip->dhostname);
		discover_target(ip);
		ip = ip->next;
	}

	if (g_data.opt & OPT_VERBOSE_INFO || g_data.opt & OPT_VERBOSE_DEBUG
			|| g_data.opt & OPT_VERBOSE_PACKET)
		fprintf(stderr, "[*] Completed host discovery\n");
	return 0;
}
