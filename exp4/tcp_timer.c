#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include "log.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;
pthread_mutex_t timer_list_lock;



// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
//	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	
	tsk->timewait.type = 0;
	tsk->timewait.enable = 1;
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
	list_add_tail(&tsk->timewait.list, &timer_list);
	log(DEBUG, "tsktimer set");
	fflush(stdout);
}


/*
1. 如果已经启用，则直接退出
2. 创建定时器，设置各个成员变量，设置timeout为比如TCP_RETRANS_INTERVAL_INITIAL
3. 增加tsk的引用计数，将定时器加入timer_list末尾
*/
void tcp_set_persist_timer(struct tcp_sock *tsk)
{
	if(tsk->persist_timer.enable)
		return ;
	
	tsk->persist_timer.type = 2;
	tsk->persist_timer.enable = 1;
	tsk->persist_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;

	tsk->ref_cnt ++;

	list_add_tail(&tsk->persist_timer.list, &timer_list);

	log(DEBUG, "tsk persist timer set");

}

/*
1. 如果已经禁用，不做任何事
2. 调用free_tcp_sock减少tsk引用计数，并从链表中移除timer
*/
void tcp_unset_persist_timer(struct tcp_sock *tsk)
{
	if(tsk->persist_timer.enable == 0)
		return ;
	
	list_delete_entry(&tsk->persist_timer.list);
	tsk->persist_timer.enable = 0;
	free_tcp_sock(tsk);
}

/*
仿照tcp_send_packet函数，发送probe报文。几处改动：
1. 发送的序列号设置为一个已经ACK过的序列号（比如tsk->snd_una - 1）
2. 不需要更新snd_nxt
3. 不需要设置重传相关内容
4. TCP负载为一个任意的字节
*/
void tcp_send_probe_packet(struct tcp_sock *tsk)
{
	int len = 1;
	char *packet = malloc(HDR_SIZE + len);
	
	strncpy((char *)(packet + HDR_SIZE), "a", len);

	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	int ip_tot_len = HDR_SIZE + len - ETHER_HDR_SIZE;
	int tcp_data_len = ip_tot_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;

	u32 saddr = tsk->sk_sip;
	u32	daddr = tsk->sk_dip;
	u16 sport = tsk->sk_sport;
	u16 dport = tsk->sk_dport;

	u32 seq = tsk->snd_una - 1;
	u32 ack = tsk->rcv_nxt;
	u16 rwnd = tsk->rcv_wnd;

	tcp_init_hdr(tcp, sport, dport, seq, ack, TCP_PSH|TCP_ACK, rwnd);
	ip_init_hdr(ip, saddr, daddr, ip_tot_len, IPPROTO_TCP); 

	tcp->checksum = tcp_checksum(ip, tcp);

	ip->checksum = ip_checksum(ip);

	ip_send_packet(packet, len + HDR_SIZE);
//	fprintf(stderr, "%d %d\n", tsk->snd_nxt, tsk->snd_una);
	assert(tsk->snd_nxt >= tsk->snd_una);
}

/*
1. 如果已经启用，则更新超时时间为当前的RTO后退出
2. 创建定时器，设置各个成员变量，初始RTO为TCP_RETRANS_INTERVAL_INITIAL。
3. 增加tsk的引用计数，将定时器加入timer_list末尾
*/
void tcp_set_retrans_timer(struct tcp_sock *tsk)
{
	if(tsk->retrans_timer.enable)
	{
		tsk->retrans_timer.timeout = tsk->rto;
		return ;
	}

	tsk->retrans_timer.enable = 1;
	tsk->retrans_timer.retrans_cnt = 0;
	tsk->retrans_timer.timeout = tsk->rto;
	tsk->retrans_timer.type = 1;

	tsk->ref_cnt ++;

	list_add_tail(&tsk->retrans_timer.list, &timer_list);
	
	log(DEBUG, "tsk retrans timer set");
}

/*
1. 如果已经禁用，不做任何事
2. 调用free_tcp_sock减少tsk引用计数，并从链表中移除timer
*/
void tcp_unset_retrans_timer(struct tcp_sock *tsk)
{
	if(!tsk->retrans_timer.enable)
		return ;
	
	
	list_delete_entry(&tsk->retrans_timer.list);
	
	tsk->retrans_timer.enable = 0;
	free_tcp_sock(tsk);
}

/*
1. 确认定时器是启用状态
2. 如果发送队列为空，则删除定时器，并且唤醒发送数据的进程。否则重置计时器，包括timeout和重传计数。

注意调用这个函数之前，需要完成对发送队列的更新。
*/
void tcp_update_retrans_timer(struct tcp_sock *tsk)
{
	if(!tsk->retrans_timer.enable)
		return ;
	
	if(list_empty(&tsk->send_buf))
	{
		tcp_unset_retrans_timer(tsk);
		log(DEBUG, "retrans timer unset");
		wake_up(tsk->wait_send);
	}
	else
	{
		tsk->retrans_timer.timeout = tsk->rto;
		tsk->retrans_timer.retrans_cnt = 0;
	}
}

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
//	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	
	struct tcp_timer *i, *j;
	struct tcp_sock *tsk;
	list_for_each_entry_safe(i, j, &timer_list, list)
	{
		if(!i->enable)
			continue;
		i->timeout -= TCP_TIMER_SCAN_INTERVAL;
		if(i->timeout > 0)
			continue;
		
		switch(i->type)
		{
			case 0:
			list_delete_entry(&i->list);
			i->enable = 0;
			tsk = (struct tcp_sock *)((char *)i - offsetof(struct tcp_sock, timewait));
			tsk->state = TCP_CLOSED;
			log(DEBUG, "tsk time up");
			tcp_bind_unhash(tsk);
			tcp_unhash(tsk);
			break;
			
			case 1:
			tsk = (struct tcp_sock *)((char *)i - offsetof(struct tcp_sock, retrans_timer));
			if(i->retrans_cnt >= 3)
			{
				log(DEBUG, "retrans time exceed");
				struct tcp_cb cb;
				struct send_buf_entry *buf = list_entry(tsk->send_buf.next, struct send_buf_entry, list);
				tcp_cb_init((struct iphdr*)buf->data + ETHER_HDR_SIZE, 
							(struct tcphdr*)buf->data + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE, &cb);
				
				tcp_send_reset(&cb);
				wake_up(tsk->wait_connect);
				wake_up(tsk->wait_send);
				wake_up(tsk->wait_recv);
				wake_up(tsk->wait_accept);

				tcp_unset_persist_timer(tsk);
				tcp_unset_retrans_timer(tsk);
				
				tcp_bind_unhash(tsk);
				tcp_unhash(tsk);
				return ;
			}
			else
			{
				log(DEBUG, "retrans timer up");
				tcp_retrans_send_buffer(tsk);
				i->retrans_cnt ++;
				i->timeout = tsk->rto;
			}
			break;

			case 2:
			tsk = (struct tcp_sock *)((char *)i - offsetof(struct tcp_sock, persist_timer));
			if(tsk->state == TCP_ESTABLISHED && tsk->snd_wnd < TCP_MSS)
			{
				tcp_send_probe_packet(tsk);
				i->timeout = TCP_RETRANS_INTERVAL_INITIAL;
			}
			else
			{
				tcp_unset_persist_timer(tsk);
				log(DEBUG, "tsk persist time up");
			}
			break;
		}
	}
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
