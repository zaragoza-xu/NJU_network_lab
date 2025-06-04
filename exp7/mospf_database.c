#include "mospf_database.h"
#include "ip.h"
#include "rtable.h"
#include "mospf_nbr.h"
#include "log.h"
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

struct list_head mospf_db;
extern ustack_t *instance;
extern pthread_mutex_t rt_lock;

void init_mospf_db()
{
	init_list_head(&mospf_db);
}

void print_lsdb(){
	if(list_empty(&mospf_db))
		return ;
	printf("LSDB:\n");
	printf("--------------------------------------\n");
	mospf_db_entry_t* lsas;
	list_for_each_entry(lsas, &mospf_db, list){
		for (int i = 0; i < lsas->nadv; ++i){
			printf("%x\t%x\t%x\t%x\t%d\t%d\t%x\n", lsas->rid, ntohl(lsas->array[i].network), ntohl(lsas->array[i].mask), ntohl(lsas->array[i].rid), lsas->seq, lsas->dis, lsas->gw);
		}
		printf("--------------------------------------\n");
	}
	fflush(stdout); 
}

mospf_db_entry_t *rid_to_db_entry(u32 rid)
{
	mospf_db_entry_t *pos;
	if(list_empty(&mospf_db))
		return NULL;
	list_for_each_entry(pos, &mospf_db, list)
	{
		if(pos->rid == rid)
			return pos;
	}
	return NULL;
}


void update_rtable()
{
	//log(DEBUG, "update rtable");
	struct list_head q;
	init_list_head(&q);
	
	mospf_db_entry_t *p;

	if(!list_empty(&mospf_db))
	{
		list_for_each_entry(p, &mospf_db, list)
		{
			init_list_head(&p->q_list);
			p->dis = MAX_DIS;
		}
	}
	iface_info_t *iface_pos;
	list_for_each_entry(iface_pos, &instance->iface_list, list)
	{
		mospf_nbr_t *nbr_pos;
		if(list_empty(&iface_pos->nbr_list))
			continue;
		list_for_each_entry(nbr_pos, &iface_pos->nbr_list, list)
		{
			mospf_db_entry_t *to = rid_to_db_entry(nbr_pos->nbr_id);
			if(to == NULL)
				continue;
			list_add_tail(&to->q_list, &q);
			
			to->dis = 1; to->gw = nbr_pos->nbr_ip; to->gw_iface = iface_pos;
		}
	}
	while(!list_empty(&q))
	{
		mospf_db_entry_t *head = list_entry(q.next, mospf_db_entry_t, q_list), *pos;
		list_for_each_entry(pos, &q, q_list)
			if(pos->dis < head->dis)
				head = pos;
		list_delete_entry(&head->q_list);

		for(int i = 0; i < head->nadv; i ++)
		{
			mospf_db_entry_t *to = rid_to_db_entry(ntohl(head->array[i].rid));
			if(to == NULL)
				continue;
			if(head->dis + 1 < to->dis)
			{
				to->dis = head->dis + 1, to->gw = head->gw;to->gw_iface = head->gw_iface;
				list_add_tail(&to->q_list, &q);
			}
		}
	}

//	print_lsdb();
	clear_rtable();

	load_rtable_from_kernel();

	pthread_mutex_lock(&rt_lock);
	if(!list_empty(&mospf_db))
	{
		list_for_each_entry(p, &mospf_db, list)
		{
			if(p->dis == MAX_DIS || p->gw == 0)
				continue;
			for(int i = 0; i < p->nadv; i ++)
			{
				rt_entry_t *pos, *entry = NULL;
				list_for_each_entry(pos, &rtable, list)
				{
					if((pos->dest & pos->mask) == (ntohl(p->array[i].network & p->array[i].mask)) && pos->mask == ntohl(p->array[i].mask))
						entry = pos;
				}
				if(entry == NULL)
				{
					entry = new_rt_entry(ntohl(p->array[i].network), ntohl(p->array[i].mask), p->gw, p->gw_iface);
					list_add_tail(&entry->list, &rtable);
				}
				else if (entry->dis > p->dis)
				{
					entry->dis = p->dis, entry->gw = p->gw, entry->iface = p->gw_iface;
					strcpy(entry->if_name, p->gw_iface->name);
				}
			}
		}
	}

	pthread_mutex_unlock(&rt_lock);
//	print_rtable();
	
}
