#ifndef __MOSPF_DATABASE_H__
#define __MOSPF_DATABASE_H__

#include "base.h"
#include "list.h"
#include "rtable.h"

#include "mospf_proto.h"

extern struct list_head mospf_db;

typedef struct {
	struct list_head list;
	u32	rid;
	u16	seq;
	int nadv;
	time_t alive;
	struct mospf_lsa *array;

	struct list_head q_list;
	u32 dis;
	u32 gw;
	iface_info_t *gw_iface;
	
} mospf_db_entry_t;

void init_mospf_db();

void print_lsdb();
mospf_db_entry_t *rid_to_db_entry(u32 rid);
void update_rtable();

#define MAX_DIS 10000

#endif
