#include "nmap.h"
#include "options.h"

void	craft_ip_packet(void *packet, struct sockaddr_in *saddr,
	struct sockaddr_in *daddr, uint8_t protocol, struct ip_options *options)
{
	struct iphdr *ip = (struct iphdr *)packet;

	/* TODO: at the moment no scan needs to set options */
	(void)options;

	/* Filling IP header */
	/* Version */
	ip->version = 4;
	/* Internet Header Length (how many 32-bit words are present in the header) */
	ip->ihl = sizeof(struct iphdr) / sizeof(uint32_t);
	/* Type of service */
	ip->tos = 0;
	/* Total length */
	ip->tot_len = htons(sizeof(packet));
	/* Identification (notes/ip.txt) */
	ip->id = 0;
	ip->frag_off = 0;
	/* TTL */
	ip->ttl = 64;
	/* Protocol (TCP) */
	ip->protocol = protocol;
	/* Checksum */
	ip->check = 0; /* Calculated by kernel */
	/* Source ip */
	ft_memcpy(&ip->saddr, &saddr->sin_addr.s_addr, sizeof(ip->saddr));
	/* Dest ip */
	ft_memcpy(&ip->daddr, &daddr->sin_addr.s_addr, sizeof(ip->daddr));
}

void	craft_tcp_packet(void *packet, struct sockaddr_in *saddr,
	struct sockaddr_in *daddr, uint8_t flags, struct tcp_options *options)
{
	struct iphdr *ip = (struct iphdr *)packet;
	struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

	/* TODO: at the moment no scan needs to set options */
	(void)options;

	/* Filling TCP header */

	/* Source port */
	tcp->source = saddr->sin_port;
	/* Destination port */
	tcp->dest = daddr->sin_port;
	/* Seq num */
	tcp->seq = htons(0);
	/* Ack num */
	tcp->ack_seq = htons(0);
	/* Sizeof header / 4 */
	tcp->doff = sizeof(struct tcphdr) /  4;
	/* Flags */
	if (flags & TH_FIN)
		tcp->fin = 1;
	if (flags & TH_SYN)
		tcp->syn = 1;
	if (flags & TH_RST)
		tcp->rst = 1;
	if (flags & TH_PUSH)
		tcp->psh = 1;
	if (flags & TH_ACK)
		tcp->ack = 1;
	if (flags & TH_URG)
		tcp->urg = 1;
	/* WTF is this */
	tcp->window = htons(64240);
	/* Checksum */
	tcp->check = 0; /* Calculated after headers */
	/* Indicates the urgent data, only if URG flag set */
	tcp->urg_ptr = 0;

	/* Checksums */
	tcp->check = tcp_checksum(ip, tcp);
}

void	craft_udp_packet(void *packet, struct sockaddr_in *saddr,
	struct sockaddr_in *daddr, char *payload, uint16_t payload_len)
{
	//struct iphdr *ip = (struct iphdr *)packet;
	struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));

	/* Source port */
	udp->uh_sport = saddr->sin_port;
	/* Destination port */
	udp->uh_dport = daddr->sin_port;

	udp->uh_ulen = htons(sizeof(struct udphdr) + payload_len);

	if (payload && payload_len > 0)
		ft_memcpy(udp + 1, payload, payload_len);
}
