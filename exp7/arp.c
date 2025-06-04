#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"
#include "log.h"
#include "mospf_proto.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void arp_init_hdr(iface_info_t *iface, u32 dst_ip, u8 dst_mac[], int op, char *packet)
{
	struct ether_arp *arp = packet_to_ether_arp(packet);
	arp->arp_hrd = htons(0x01), arp->arp_hln = 6;
	arp->arp_pro = htons(0x0800), arp->arp_pln = 4;
	arp->arp_spa = htonl(iface->ip), arp->arp_tpa = htonl(dst_ip);
	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
	memcpy(arp->arp_tha, dst_mac, ETH_ALEN);

	arp->arp_op = htons(op);
}

// send an arp reply packet
// Encapsulate an arp reply packet, send it out through iface_send_packet.
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
//	log(DEBUG, "send arp reply");
	char *packet = malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));

	struct ether_header *eth = (void *)packet;
	memcpy(eth->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	memcpy(eth->ether_shost, iface->mac, ETH_ALEN);
	eth->ether_type = htons(ETH_P_ARP);

	arp_init_hdr(iface, ntohl(req_hdr->arp_spa), req_hdr->arp_sha, ARPOP_REPLY, packet);

	iface_send_packet(iface, packet, ETHER_HDR_SIZE+ sizeof(struct ether_arp));
}

// send an arp request
// Encapsulate an arp request packet, send it out through iface_send_packet.
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
//	log(DEBUG, "send arp request from %s", iface->ip_str);
	char *packet = malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));

	struct ether_header *eth = (void *)packet;
	u8 broadcast_addr[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	memcpy(eth->ether_dhost, broadcast_addr, ETH_ALEN);
	memcpy(eth->ether_shost, iface->mac, ETH_ALEN);
	eth->ether_type = htons(ETH_P_ARP);

	arp_init_hdr(iface, dst_ip, (u8 [6]){0, 0, 0, 0, 0, 0}, ARPOP_REQUEST, packet);

	iface_send_packet(iface, packet, ETHER_HDR_SIZE+ sizeof(struct ether_arp));

}

// handle arp packet
// If the dest ip address of this arp packet is not equal to the ip address of the incoming iface, drop it.
// If it is an arp request packet, send arp reply to the destination, insert the ip->mac mapping into arpcache.
// If it is an arp reply packet, insert the ip->mac mapping into arpcache.
// Tips:
// You can use functions: htons, htonl, ntohs, ntohl to convert host byte order and network byte order (16 bits use ntohs/htons, 32 bits use ntohl/htonl).
// You can use function: packet_to_ether_arp() in arp.h to get the ethernet header in a packet.
void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp *arp = packet_to_ether_arp(packet);
//	log(DEBUG, "%s received arp packet, type %d", iface->ip_str, ntohs(arp->arp_op));
	if(ntohl(arp->arp_tpa) != iface->ip)
	{
		free(packet);
		return ;
	}
	if(ntohs(arp->arp_op) == ARPOP_REQUEST)
	{
//		log(DEBUG, "%s received arp request", iface->ip_str);
		arpcache_insert(ntohl(arp->arp_spa), arp->arp_sha);
		arp_send_reply(iface, arp);
	}
	if(ntohs(arp->arp_op) == ARPOP_REPLY)
	{
//		log(DEBUG, "%s received arp reply", iface->ip_str);
		arpcache_insert(ntohl(arp->arp_spa), arp->arp_sha);
	}
	free(packet);
}

// send (IP) packet through arpcache lookup 
// Lookup the mac address of dst_ip in arpcache.
// If it is found, fill the ethernet header and emit the packet by iface_send_packet.
// Otherwise, pending this packet into arpcache and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	u8 dst_mac[ETH_ALEN];
	if(dst_ip == MOSPF_ALLSPFRouters)
	{
		memcpy(dst_mac, (u8[ETH_ALEN]){
            0x01, 0x00, 0x5e,
            (u8)(((dst_ip >> 16) & 0xff) & 0x7f), 
            (u8)((dst_ip >> 8) & 0xff),           
            (u8)(dst_ip & 0xff)                   
        }, ETH_ALEN);
	}
	else if(arpcache_lookup(dst_ip, dst_mac) == 0)
	{
		// pend
//		log(DEBUG, "pend dest %x for arp request", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
		return ;
	}
//	log(DEBUG, "iface sent packet from %s to %x by arp", iface->ip_str, dst_ip);
	struct ether_header *eth = (struct ether_header *)packet;
	memcpy(eth->ether_dhost, dst_mac, ETH_ALEN);
	memcpy(eth->ether_shost, iface->mac, ETH_ALEN);
	eth->ether_type = htons(ETH_P_IP);
	iface_send_packet(iface, packet, len);
}
