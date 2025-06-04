#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"
#include "arp.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;

#define MOSPF_TOT_HDR_SIZE (ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE)
void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);

void send_mospf_lsu();

void mospf_run()
{
	pthread_t hello, lsu, nbr, db;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);
}

void *sending_mospf_hello_thread(void *param)
{
	while(1)
	{
		iface_info_t *iface_pos;
		//log(DEBUG, "broadcast hello");
		//pthread_mutex_lock(&mospf_lock);
		list_for_each_entry(iface_pos, &instance->iface_list, list)
		{
			u32 len = MOSPF_TOT_HDR_SIZE + MOSPF_HELLO_SIZE;
			char *packet = malloc(len);
			struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
			struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_BASE_HDR_SIZE);
			struct mospf_hello *hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
			mospf_init_hello(hello, iface_pos->mask);
			mospf_init_hdr(mospf, MOSPF_TYPE_HELLO, len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE, instance->router_id, instance->area_id);
			//log(DEBUG, "rid %d, ver %d, seq %d", instance->router_id, mospf->version, instance->sequence_num);
			ip_init_hdr(ip, iface_pos->ip, MOSPF_ALLSPFRouters, len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
			iface_send_packet_by_arp(iface_pos, MOSPF_ALLSPFRouters, packet, len);
		}
		//pthread_mutex_unlock(&mospf_lock);
		sleep(MOSPF_DEFAULT_HELLOINT);
	}
	return NULL;
}

void *sending_mospf_lsu_thread(void *param)
{
	while(1)
	{
		
		//log(DEBUG, "broadcast lsu");
		pthread_mutex_lock(&mospf_lock);
		send_mospf_lsu();
		pthread_mutex_unlock(&mospf_lock);
		sleep(MOSPF_DEFAULT_LSUINT);
	}

	return NULL;
}

void *checking_nbr_thread(void *param)
{
	while(1)
	{
		sleep(1);
		pthread_mutex_lock(&mospf_lock);
		int update = 0;
		iface_info_t *iface_pos;
		list_for_each_entry(iface_pos, &instance->iface_list, list)
		{
			mospf_nbr_t *nbr_pos, *q;

			if(!list_empty(&iface_pos->nbr_list))
			list_for_each_entry_safe(nbr_pos, q, &iface_pos->nbr_list, list)
			{
				if((-- nbr_pos->alive) <= 0)
				{
					list_delete_entry(&nbr_pos->list);
					update = 1;
					iface_pos->num_nbr --;
					free(nbr_pos);
				}
			}
		}
		if(update)
		{
			//log(DEBUG, "check nbr, broadcast lsas");
			send_mospf_lsu();
			update_rtable();
		}
		
		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void *checking_database_thread(void *param)
{
	while(1)
	{
		sleep(1);

		pthread_mutex_lock(&mospf_lock);
		int update = 0;
		mospf_db_entry_t *pos, *q;

		if(!list_empty(&mospf_db))
		list_for_each_entry_safe(pos, q, &mospf_db, list)
		{
			if((-- pos->alive) <= 0)
			{
				list_delete_entry(&pos->list);
				update = 1;
				free(pos->array);
				free(pos);
			}
		}

		if(update)
		{
			//log(DEBUG, "check db");
			update_rtable();
		}
		
		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}


struct mospf_lsa *create_lsa()
{
	struct mospf_lsa *new_lsa;
	u32 nadv = 0, i = 0;
	iface_info_t *iface_pos;
	list_for_each_entry(iface_pos, &instance->iface_list, list)
	{
		if(iface_pos->num_nbr == 0)
			nadv ++;
		nadv += iface_pos->num_nbr;
	}
	new_lsa = calloc(nadv, MOSPF_LSA_SIZE);
	list_for_each_entry(iface_pos, &instance->iface_list, list)
	{
		mospf_nbr_t *nbr_pos;

		if(list_empty(&iface_pos->nbr_list))
		{
			new_lsa[i ++] = (struct mospf_lsa){.mask = htonl(iface_pos->mask), .network = htonl(iface_pos->ip)};
		}
		list_for_each_entry(nbr_pos, &iface_pos->nbr_list, list)
		{
			new_lsa[i ++] = (struct mospf_lsa){.mask = htonl(nbr_pos->nbr_mask), .network = htonl(nbr_pos->nbr_ip), .rid = htonl(nbr_pos->nbr_id)};
		}
		
	}
	
	return new_lsa;
}

void send_mospf_lsu()
{
	u32 nadv = 0;
	iface_info_t *iface_pos;
	list_for_each_entry(iface_pos, &instance->iface_list, list)
	{
		if(iface_pos->num_nbr == 0)
			nadv ++;
		nadv += iface_pos->num_nbr;
	}
		
	struct mospf_lsa *new_lsa = create_lsa();

/*	log(DEBUG, "lsu: nadv %d", nadv);
	printf("--------------------------------------\n");
	for(int i = 0; i < nadv; i ++)
	{
		printf("%x\t%x\t%x\n", new_lsa[i].rid, ntohl(new_lsa[i].network), ntohl(new_lsa[i].network));
	}
	printf("--------------------------------------\n");
	fflush(stdout);*/

	u32 len = MOSPF_TOT_HDR_SIZE + MOSPF_LSU_SIZE + nadv * MOSPF_LSA_SIZE;

	list_for_each_entry(iface_pos, &instance->iface_list, list)
	{
		mospf_nbr_t *nbr_pos, *q;

		if(!list_empty(&iface_pos->nbr_list))
		list_for_each_entry_safe(nbr_pos, q, &iface_pos->nbr_list, list)
		{
			char *packet = malloc(len);
			struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
			struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_BASE_HDR_SIZE);
			struct mospf_lsu *lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
			struct mospf_lsa *lsa = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);
			memcpy(lsa, new_lsa, nadv * MOSPF_LSA_SIZE);

			mospf_init_lsu(lsu, nadv);
			mospf_init_hdr(mospf, MOSPF_TYPE_LSU, len - IP_BASE_HDR_SIZE - ETHER_HDR_SIZE, instance->router_id, instance->area_id);

			ip_init_hdr(ip, iface_pos->ip, nbr_pos->nbr_ip, len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
			iface_send_packet_by_arp(iface_pos, nbr_pos->nbr_ip, packet, len);
			// packet freed
		}
		
	}
	free(new_lsa);
	
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	pthread_mutex_lock(&mospf_lock);
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_hello *hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
	mospf_nbr_t *pos, *from = NULL;
	int inserted = 0;
	list_for_each_entry(pos, &iface->nbr_list, list)
		if((pos->nbr_ip & pos->nbr_mask) == ntohl(ip->saddr & hello->mask))
			from = pos;
	if(!from)
	{
		//log(DEBUG, "create new nbr_entry %x", ntohl(ip->saddr & hello->mask));
		from = (mospf_nbr_t *)malloc(sizeof(mospf_nbr_t));
		iface->num_nbr ++;
	}
	else
		list_delete_entry(&from->list);
	*from = (mospf_nbr_t){.alive = MOSPF_HELLO_TIMEOUT, .nbr_id = ntohl(mospf->rid), .nbr_ip = ntohl(ip->saddr), .nbr_mask = ntohl(hello->mask)};
	list_add_tail(&from->list, &iface->nbr_list);

	//log(DEBUG, "received hello, broadcasting lsu");
	update_rtable();
	send_mospf_lsu();
	
	pthread_mutex_unlock(&mospf_lock);
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	pthread_mutex_lock(&mospf_lock);
	
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_lsu *lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
	struct mospf_lsa *lsa = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);
	mospf_db_entry_t *db_entry = rid_to_db_entry(ntohl(mospf->rid));

	if(ntohl(mospf->rid) == instance->router_id || lsu->ttl <= 0)
	{
		pthread_mutex_unlock(&mospf_lock);
		return ;
	}
	
	if(db_entry == NULL)
	{
		db_entry = calloc(1, sizeof(mospf_db_entry_t));
	}
	else if(db_entry->seq < ntohs(lsu->seq))
	{
		list_delete_entry(&db_entry->list);	
	}
	else
	{
		pthread_mutex_unlock(&mospf_lock);
		return ;
	}
	//log(DEBUG, "receive lsu seq %d, old seq %d, update rtable and forward it", ntohs(lsu->seq), db_entry->seq);
	if(db_entry->array != NULL)
		free(db_entry->array);
	*db_entry = (mospf_db_entry_t){.alive = MOSPF_DATABASE_TIMEOUT, .dis = MAX_DIS, .nadv = ntohl(lsu->nadv), .rid = ntohl(mospf->rid), .seq = ntohs(lsu->seq)};
	db_entry->array = calloc(db_entry->nadv, MOSPF_LSA_SIZE);
	memcpy(db_entry->array, lsa, db_entry->nadv * MOSPF_LSA_SIZE);
	list_add_tail(&db_entry->list, &mospf_db);
	
	update_rtable();
	
	iface_info_t *iface_pos;
	list_for_each_entry(iface_pos, &instance->iface_list, list)
	{
		if(iface_pos == iface)
			continue;
		mospf_nbr_t *nbr_pos, *q;

		if(!list_empty(&iface_pos->nbr_list))
		list_for_each_entry_safe(nbr_pos, q, &iface_pos->nbr_list, list)
		{
			//log(DEBUG, "%s nbr %x\n", iface_pos->name, nbr_pos->nbr_ip);
			fflush(stdout);
			char *new_pkt = malloc(len);
			memcpy(new_pkt, packet, len);
			struct iphdr *new_ip = (struct iphdr *)(new_pkt + ETHER_HDR_SIZE);
			struct mospf_hdr *new_mospf = (struct mospf_hdr *)((char *)new_ip + IP_BASE_HDR_SIZE);
			struct mospf_lsu *new_lsu = (struct mospf_lsu *)((char *)new_mospf + MOSPF_HDR_SIZE);
			new_lsu->ttl --;
			new_mospf->checksum = mospf_checksum(new_mospf);
			ip_init_hdr(new_ip, iface_pos->ip, nbr_pos->nbr_ip, len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
			
			iface_send_packet_by_arp(iface_pos, nbr_pos->nbr_ip, new_pkt, len);
		}
		
	}
	pthread_mutex_unlock(&mospf_lock);
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	
	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}
