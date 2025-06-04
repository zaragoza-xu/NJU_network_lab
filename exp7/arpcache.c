#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweep thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// look up the IP->mac mapping, need pthread_mutex_lock/unlock
// Traverse the table to find whether there is an entry with the same IP and mac address with the given arguments.
int arpcache_lookup(u32 ip4, u8 mac[])
{
	pthread_mutex_lock(&arpcache.lock);
	for(int i = 0; i < MAX_ARP_SIZE; i ++)
	{
		if(arpcache.entries[i].valid && ip4 == arpcache.entries[i].ip4)
		{
			memcpy(mac, arpcache.entries[i].mac, ETH_ALEN);
			
			pthread_mutex_unlock(&arpcache.lock);
			return 1;
		}
	}
//	log(DEBUG, "arp cache lookup failed");
	pthread_mutex_unlock(&arpcache.lock);
	return 0;
}

// insert the IP->mac mapping into arpcache, need pthread_mutex_lock/unlock
// If there is a timeout entry (attribute valid in struct) in arpcache, replace it.
// If there isn't a timeout entry in arpcache, randomly replace one.
// If there are pending packets waiting for this mapping, fill the ethernet header for each of them, and send them out.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(用arp_req结构体封装)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_insert(u32 ip4, u8 mac[])
{
	pthread_mutex_lock(&arpcache.lock);
	int inserted = 0;
	for(int i = 0; i < MAX_ARP_SIZE; i ++)
	{
		if(!arpcache.entries[i].valid)
		{
			inserted = 1;
			arpcache.entries[i] = (struct arp_cache_entry){.ip4 = ip4, .added = time(NULL), .valid = 1};
			memcpy(arpcache.entries[i].mac, mac, ETH_ALEN);
			break;
		}
	}
	if(!inserted)
	{
		arpcache.entries[0] = (struct arp_cache_entry){.ip4 = ip4, .added = time(NULL), .valid = 1};
		memcpy(arpcache.entries[0].mac, mac, ETH_ALEN);
	}
//	log(DEBUG, "inserted arp cache entry %d", ip4);
	struct arp_req *p, *pq;
	list_for_each_entry_safe(p, pq, &arpcache.req_list, list)
	{
		if(p->ip4 == ip4 && !list_empty(&p->cached_packets))
		{
			struct cached_pkt *pos, *q;
			list_for_each_entry_safe(pos, q, &p->cached_packets, list)
			{
				struct ether_header *eth = (struct ether_header *)pos->packet;
				memcpy(eth->ether_dhost, mac, ETH_ALEN);
				memcpy(eth->ether_shost, p->iface->mac, ETH_ALEN);
				eth->ether_type = htons(ETH_P_IP);
				
//				log(DEBUG, "sent cached packet from %s", p->iface->ip_str);
				iface_send_packet(p->iface, pos->packet, pos->len);
				list_delete_entry(&pos->list);
				free(pos);
			}
			list_delete_entry(&p->list);
			free(p);
		}
	}
	pthread_mutex_unlock(&arpcache.lock);

}

// append the packet to arpcache
// Look up in the list which stores pending packets, if there is already an entry with the same IP address and iface, 
// which means the corresponding arp request has been sent out, just append this packet at the tail of that entry (The entry may contain more than one packet).
// Otherwise, malloc a new entry with the given IP address and iface, append the packet, and send arp request.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	pthread_mutex_lock(&arpcache.lock);
	struct arp_req *p;
	int appended = 0;
	if(!list_empty(&arpcache.req_list))
	list_for_each_entry(p, &arpcache.req_list, list)
	{
		if(p->ip4 == ip4)
		{
			struct cached_pkt *new_pkt = malloc(sizeof(struct cached_pkt));
			new_pkt->len = len, new_pkt->packet = packet;
			init_list_head(&new_pkt->list);
			list_add_tail(&new_pkt->list, &p->cached_packets);
			appended = 1;
		}
	}
	if(!appended)
	{
		struct arp_req *new_req = malloc(sizeof(struct arp_req));
		*new_req = (struct arp_req){.iface = iface, .ip4 = ip4, .sent = time(NULL), .retries = 0};
		init_list_head(&new_req->cached_packets);
		init_list_head(&new_req->list);
		list_add_tail(&new_req->list, &arpcache.req_list);

		struct cached_pkt *new_pkt = malloc(sizeof(struct cached_pkt));
		new_pkt->len = len, new_pkt->packet = packet;
		init_list_head(&new_pkt->list);
		list_add_tail(&new_pkt->list, &new_req->cached_packets);
		//log(DEBUG, "create new arp_req entry");
		arp_send_request(iface, ip4);
	}
	//log(DEBUG, "appended packet into arpcache");
	pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
// for IP->mac entry, if the entry has been in the table for more than 15 seconds, remove it from the table
// for pending packets, if the arp request is sent out 1 second ago, while the reply has not been received, retransmit the arp request
// If the arp request has been sent 5 times without receiving arp reply, for each pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these packets
// tips
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void *arpcache_sweep(void *arg) 
{
	while (1) {
		sleep(1);
		pthread_mutex_lock(&arpcache.lock);
		time_t cur_time = time(NULL);
		for(int i = 0; i < MAX_ARP_SIZE; i ++)
		{
			if(cur_time - arpcache.entries[i].added > ARP_ENTRY_TIMEOUT)
			{
				arpcache.entries[i].valid = 0;
			}
		}
		struct arp_req *p, *q;
		if(!list_empty(&arpcache.req_list))
		list_for_each_entry_safe(p, q, &arpcache.req_list, list)
		{
			if(!list_empty(&p->cached_packets) && cur_time - p->sent >= 1)
			{
				if(p->retries < 4)
				{
					arp_send_request(p->iface, p->ip4);
					p->retries ++, p->sent = cur_time;
					//log(DEBUG, "arp request retry, cnt %d", p->retries);
				}
				else
				{
					struct cached_pkt *p_pkt, *q_pkt;
					list_for_each_entry_safe(p_pkt, q_pkt, &p->cached_packets, list)
					{
						pthread_mutex_unlock(&arpcache.lock);
						icmp_send_packet(p_pkt->packet, p_pkt->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
						pthread_mutex_lock(&arpcache.lock);
						list_delete_entry(&p_pkt->list);
						free(p_pkt);
					}
					list_delete_entry(&p->list);
					free(p);
				}
			}
		}
		pthread_mutex_unlock(&arpcache.lock);
	}

	return NULL;
}
