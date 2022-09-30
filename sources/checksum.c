#include "nmap.h"

unsigned short checksum(const char *buf, unsigned int size)
{
	unsigned sum = 0, i;

	/* Accumulate checksum */
	for (i = 0; i < size - 1; i += 2) {
		unsigned short word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}

	/* Handle odd-sized case */
	if (size & 1) {
		unsigned short word16 = (unsigned char) buf[i];
		sum += word16;
	}

	/* Fold to get the ones-complement result */
	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

	/* Invert to get the negative in ones-complement arithmetic */
	return ~sum;
}

unsigned short tcp_checksum(struct iphdr *ip, struct tcphdr *tcp)
{
	struct pseudo_header
	{
		u_int32_t source_address;
		u_int32_t dest_address;
		u_int8_t placeholder;
		u_int8_t protocol;
		u_int16_t tcp_length;
	} psh;

	char ppacket[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];

	psh.source_address = ip->saddr;
	psh.dest_address = ip->daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	/* TODO: Options calculation */
	psh.tcp_length = htons(sizeof(struct tcphdr));

	ft_memcpy(ppacket, (char*)&psh, sizeof(struct pseudo_header));
	ft_memcpy(ppacket+sizeof(struct pseudo_header),
		tcp, sizeof(struct tcphdr));

	return checksum(ppacket, sizeof(ppacket));
}
