#include "mac.h"
#include "log.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

mac_port_map_t mac_port_map;

// initialize mac_port table
void init_mac_port_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	for (int i = 0; i < HASH_8BITS; i++) {
		init_list_head(&mac_port_map.hash_table[i]);
	}

	pthread_mutex_init(&mac_port_map.lock, NULL);

	pthread_create(&mac_port_map.thread, NULL, sweeping_mac_port_thread, NULL);
}

// destroy mac_port table
void destory_mac_port_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry, *q;
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[i], list) {
			list_delete_entry(&entry->list);
			free(entry);
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

// lookup the mac address in mac_port table
iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	// TODO: implement the lookup process here
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *pos;
	u8 hash = hash8((char *)mac, ETH_ALEN);
	list_for_each_entry(pos, &mac_port_map.hash_table[hash], list)
	{
		if(!memcmp(pos->mac, mac, ETH_ALEN))
		{
			pthread_mutex_unlock(&mac_port_map.lock);
			return pos->iface;
		}
			
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	return NULL;
}

// insert the mac -> iface mapping into mac_port table
void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	// TODO: implement the insertion process here
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *pos, *q;
	u8 hash = hash8((char *)mac, ETH_ALEN);
	list_for_each_entry_safe(pos, q, &mac_port_map.hash_table[hash], list)
	{
		if(!memcmp(pos->mac, mac, ETH_ALEN))
		{
			pos->iface = iface;
			pos->visited = time(NULL);

			pthread_mutex_unlock(&mac_port_map.lock);
			return ;
		}
	}
	mac_port_entry_t *new = malloc(sizeof(mac_port_entry_t));
	*new = (mac_port_entry_t){.iface = iface, .visited = time(NULL)};
	init_list_head(&new->list);
	memcpy(new->mac, mac, ETH_ALEN);
	list_add_tail(&new->list, &mac_port_map.hash_table[hash]);
	pthread_mutex_unlock(&mac_port_map.lock);
}

// dumping mac_port table
void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry(entry, &mac_port_map.hash_table[i], list) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

// sweeping mac_port table, remove the entry which has not been visited in the
// last 30 seconds.
int sweep_aged_mac_port_entry()
{
	// TODO: implement the sweeping process here
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *pos, *q;
	int del = 0;
	for(int i = 0; i < HASH_8BITS; i ++)
	{
		list_for_each_entry_safe(pos, q, &mac_port_map.hash_table[i], list)
		{
			if(time(NULL) - pos->visited > 30)
			{
				list_delete_entry(&pos->list);
				free(pos);
				del ++;
			}
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	return del;
}

// sweeping mac_port table periodically, by calling sweep_aged_mac_port_entry
void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.", n);
	}

	return NULL;
}
