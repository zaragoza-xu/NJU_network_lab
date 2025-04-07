#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include "log.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;
pthread_mutex_t timer_list_lock;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
//	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	
	struct tcp_sock *tmp, *q;
	list_for_each_entry_safe(tmp, q, &timer_list, timewait.list)
	{
		if(tmp->timewait.enable)
			tmp->timewait.timeout -= TCP_TIMER_SCAN_INTERVAL;
		if(tmp->timewait.timeout <= 0)
		{
			if(tmp->timewait.type == 0)
			{
				
				list_delete_entry(&tmp->timewait.list);
				tmp->timewait.enable = 0;
				tmp->state = TCP_CLOSED;
				log(DEBUG, "tsk time up");
				if(!tmp->parent)
					tcp_bind_unhash(tmp);
				tcp_unhash(tmp);
				break;
			}
		}
	}
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
//	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	list_add_tail(&tsk->timewait.list, &timer_list);
	tsk->timewait.type = 0;
	tsk->timewait.enable = 1;
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
	log(DEBUG, "tsktimer set");
	fflush(stdout);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	pthread_mutex_init(&timer_list_lock, NULL);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		pthread_mutex_lock(&timer_list_lock);
		tcp_scan_timer_list();
		pthread_mutex_unlock(&timer_list_lock);
	}

	return NULL;
}
