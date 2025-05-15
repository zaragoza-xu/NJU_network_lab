#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// When forwarding the packet, you should check the TTL, update the checksum and TTL.
// Then, determine the next hop to forward the packet, then send the packet by iface_send_packet_by_arp.
// The interface to forward the packet is specified by longest_prefix_match.
void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	log(DEBUG, "forwarding ip/icmp packet");
	struct iphdr *ip = packet_to_ip_hdr(packet);
	ip->ttl --;
	if(ip->ttl == 0)
	{
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, 0);
		return ;
	}
	ip->checksum = ip_checksum(ip);

	rt_entry_t *nxt_hop = longest_prefix_match(ip_dst);
	if(nxt_hop == NULL)
	{
		
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		return ;
	}

	if(nxt_hop->gw == 0)
	{
		iface_send_packet_by_arp(nxt_hop->iface, ip_dst, packet, len);
	}
	else
	{
		iface_send_packet_by_arp(nxt_hop->iface, nxt_hop->gw, packet, len);
	}

}

// If the packet is ICMP echo request and the destination IP address is equal to the IP address of the iface, send ICMP echo reply.
// Otherwise, forward the packet.
// Tips:
// You can use struct iphdr *ip = packet_to_ip_hdr(packet); in ip.h to get the ip header in a packet.
// You can use struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip); in ip.h to get the icmp header in a packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{

	struct iphdr *ip = packet_to_ip_hdr(packet);
	log(DEBUG, "received ip/icmp packet from %s", iface->ip_str);
	if(ntohl(ip->daddr) == iface->ip)
	{
		
		struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
		if(icmp->type == 8 && icmp->code == 0)
			icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
		return ;
	}
	
	ip_forward_packet(ntohl(ip->daddr), packet, len);
}