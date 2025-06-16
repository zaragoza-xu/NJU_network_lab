#include "base.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern ustack_t *instance;

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// TODO: broadcast packet 
	iface_info_t *p;
	list_for_each_entry(p, &instance->iface_list, list)
	{
		if(p != iface)
		{
			char *new_pkt = malloc(len);
			memcpy(new_pkt, packet, len);
			iface_send_packet(p, new_pkt, len);
		}
	}
}
