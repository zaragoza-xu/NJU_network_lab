#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

#define HDR_SIZE(ip) (ETHER_HDR_SIZE + ip->ihl * 4)

// icmp_send_packet has two main functions:
// 1.handle icmp packets sent to the router itself (ICMP ECHO REPLY).
// 2.when an error occurs, send icmp error packets.
// Note that the structure of these two icmp packets is different, you need to malloc different sizes of memory.
// Some function and macro definitions in ip.h/icmp.h can help you.
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	struct iphdr *in_ip = packet_to_ip_hdr(in_pkt);
	char *out_pkt;
	struct iphdr *out_ip;
	struct icmphdr *out_icmp;
	switch(type)
	{
		case ICMP_ECHOREPLY:
		out_pkt = malloc(len);
		memcpy(out_pkt, in_pkt, len);

		out_ip = packet_to_ip_hdr(out_pkt);
		out_icmp = (struct icmphdr *)IP_DATA(out_ip);
		out_icmp->code = code, out_icmp->type = type;
		out_icmp->checksum = icmp_checksum(out_icmp, len - HDR_SIZE(in_ip));

		log(DEBUG, "icmp echoreply");
		ip_send_packet(out_pkt, len);
		break;
//--------------------------------------------------------------

		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		
		size_t out_pkt_len = HDR_SIZE(in_ip) + ICMP_HDR_SIZE + in_ip->ihl * 4 + 8;
		out_pkt = malloc(out_pkt_len);
		memcpy(out_pkt, in_pkt, HDR_SIZE(in_ip) + ICMP_HDR_SIZE);
		memcpy(out_pkt + ICMP_HDR_SIZE + HDR_SIZE(in_ip), in_ip, in_ip->ihl * 4 + 8);

		out_ip = packet_to_ip_hdr(out_pkt);
		out_ip->tot_len = htons(out_pkt_len - ETHER_HDR_SIZE);
		out_icmp = (struct icmphdr *)IP_DATA(out_ip);
		out_icmp->type = type, out_icmp->code = code;
		out_icmp->icmp_identifier = out_icmp->icmp_sequence = 0;
		out_icmp->checksum = icmp_checksum(out_icmp, out_pkt_len - HDR_SIZE(in_ip));
		//log(DEBUG, "icmp checksum %x %ld, %ld", out_icmp->checksum, out_pkt_len - HDR_SIZE(in_ip);
		log(DEBUG, "icmp dest unreach");
		
		ip_send_packet(out_pkt, out_pkt_len);
		break;

		
		default:
		log(DEBUG, "undefined");

	}

}
