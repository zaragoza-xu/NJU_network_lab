#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	int old_snd_wnd = tcp_tx_window_test(tsk);
	tsk->adv_wnd = cb->rwnd;
	tsk->snd_una = cb->ack;
	tsk->snd_wnd = tsk->adv_wnd;
	log(DEBUG, "snd_una %d, snd_wnd %d, rcv_free %d, test %d", tsk->snd_una, tsk->snd_wnd, ring_buffer_free(tsk->rcv_buf), tcp_tx_window_test(tsk));
	if(!tcp_tx_window_test(tsk))
		tcp_set_persist_timer(tsk);
	else
		tcp_unset_persist_timer(tsk);
	
	if (old_snd_wnd == 0 && tcp_tx_window_test(tsk))
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

/*
遍历rcv_ofo_buf，将所有有序的（序列号等于tsk->rcv_nxt）的报文送入接收队列（tsk->rcv_buf）
更新rcv_nxt, rcv_wnd并唤醒接收线程(wait_recv)

如果接收队列已满，应当退出函数，而非等待。
*/
int tcp_move_rcv_ofo_buf(struct tcp_sock *tsk)
{
	struct rcv_ofo_buf_entry *pos, *q;
	list_for_each_entry_safe(pos, q, &tsk->rcv_ofo_buf, list)
	{
		log(DEBUG, "rcv_ofo_buf: %d %d", pos->seq, tsk->rcv_nxt);
		if(pos->seq == tsk->rcv_nxt)
		{
			log(DEBUG, "tcp_process write: attempt to acquire rcv_buf_lock %p", tsk);
			pthread_mutex_lock(&tsk->rcv_buf_lock);
			log(DEBUG, "tcp_process write: rcv_buf_lock acquired");

			if(ring_buffer_free(tsk->rcv_buf) < pos->len)
				return -1;
			write_ring_buffer(tsk->rcv_buf, pos->data, pos->len);
			tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
			
			pthread_mutex_unlock(&tsk->rcv_buf_lock);
			log(DEBUG, "tcp_process write: rcv_buf_lock released");

			log(DEBUG, "moved a packet");
			
			tsk->rcv_nxt = pos->seq_end;

			list_delete_entry(&pos->list);
			wake_up(tsk->wait_recv);
		}
	}
	return 0;
}

/*
1. 创建recv_ofo_buf_entry
2. 用list_for_each_entry_safe遍历rcv_ofo_buf，将表项插入合适的位置。如果发现了重复数据包，则丢弃当前数据。
3. 调用tcp_move_recv_ofo_buffer执行报文上送
return -1 on error, 0 on normal
*/
int tcp_rcv_ofo_buffer_add_packet(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	struct rcv_ofo_buf_entry *buf = malloc(sizeof(struct rcv_ofo_buf_entry) + cb->pl_len + 1);

	memcpy(buf->data, cb->payload, cb->pl_len);
	buf->len = cb->pl_len;
	buf->seq = cb->seq;
	buf->seq_end = cb->seq_end;
	init_list_head(&buf->list);

	struct rcv_ofo_buf_entry *pos, *q;
	if(list_empty(&tsk->rcv_ofo_buf))
	{
		list_add_tail(&buf->list, &tsk->rcv_ofo_buf);
	}
	else
	{
		list_for_each_entry_safe(pos, q, &tsk->rcv_ofo_buf, list)
		{
			if(pos->seq == buf->seq)
				return -1;
			if(pos->seq < buf->seq && (&q->list == &tsk->rcv_ofo_buf || q->seq > buf->seq))
			{
				list_insert(&buf->list, &pos->list, &q->list);
			}
		}
	}
	tcp_move_rcv_ofo_buf(tsk);
	tcp_send_control_packet(tsk, TCP_ACK);
	log(DEBUG, "received a packet");
	
	return 0;
}

// process data packet sent by peer
void process_data_packet(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	if((cb->flags & TCP_ACK) && cb->pl_len == 0)
	{
		tcp_update_window_safe(tsk, cb);
		tcp_update_send_buffer(tsk, cb->ack);
	}
	if(is_tcp_seq_valid(tsk, cb) != 0 && cb->pl_len > 0)
	{
		log(DEBUG, "attempt to acquire rcv_ofo_buf_lock");
		pthread_mutex_lock(&tsk->rcv_ofo_buf_lock);
		log(DEBUG, "rcv_ofo_buf_lock acquired");

		tcp_rcv_ofo_buffer_add_packet(tsk, cb);

		pthread_mutex_unlock(&tsk->rcv_ofo_buf_lock);
		log(DEBUG, "rcv_ofo_buf_lock released");
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
//	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	
	if(cb->flags == TCP_RST)
	{
		tcp_unhash(tsk);
		tcp_bind_unhash(tsk);
		return ;
	}
	switch(tsk->state)
	{
		case TCP_LISTEN:
		if(cb->flags & TCP_SYN)
		{
			struct tcp_sock *child_tsk = alloc_tcp_sock();
			child_tsk->local = (struct sock_addr){cb->daddr, cb->dport};
			child_tsk->peer = (struct sock_addr){cb->saddr, cb->sport};
			child_tsk->parent = tsk;
			
			child_tsk->iss = tcp_new_iss();
			child_tsk->snd_nxt = child_tsk->iss;
			child_tsk->snd_una = child_tsk->iss;
			child_tsk->rcv_nxt = cb->seq_end;

			child_tsk->state = TCP_SYN_RECV;
			list_add_tail(&child_tsk->list, &tsk->listen_queue);
			tcp_send_control_packet(child_tsk, TCP_SYN | TCP_ACK);
			log(DEBUG, "received SYN from client. reply SYN | ACK");
		}
		if(cb->flags & TCP_ACK)
		{
			struct tcp_sock *child_tsk;
			if((child_tsk = tcp_sock_lookup_listen_queue(tsk, cb)) == NULL)
			{
				log(ERROR, "received tcp packet to invalid listen port, drop it.");
				
				break;
			}
			if(!tcp_sock_accept_queue_full(tsk))
			{
				
				tcp_sock_accept_enqueue(child_tsk);
				child_tsk->state = TCP_ESTABLISHED;
				tcp_hash(child_tsk);

				tcp_update_window_safe(child_tsk, cb);
				tcp_update_send_buffer(child_tsk, cb->ack);
				log(DEBUG, "received ACK from client. connection established.");
				wake_up(tsk->wait_accept);
			}
			else
			{
				log(ERROR, "socket accept queue is full, drop it.");
			}
		}
		break;
// ------------------------------------------------------------------
		case TCP_SYN_SENT:
		if((cb->flags | TCP_ACK) && (cb->flags | TCP_SYN))
		{
			tcp_update_window_safe(tsk, cb);
			tcp_update_send_buffer(tsk, cb->ack);

			tsk->rcv_nxt = cb->seq_end;
			if(wake_up(tsk->wait_connect) < 0)
				log(ERROR, "no waiting connection.");
			else
				log(DEBUG, "received SYN | ACK from server. connection established.");
		}
		break;


// --------------------------------------------------------------------
// --------------------------------------------------------------------
// --------------------------------------------------------------------
		
		case TCP_ESTABLISHED:
		process_data_packet(tsk, cb, packet);
		if((cb->flags & TCP_FIN) && cb->seq == tsk->rcv_nxt)
		{
			tsk->rcv_nxt = cb->seq_end;
			tcp_send_control_packet(tsk, TCP_ACK);
			tsk->state = TCP_CLOSE_WAIT;
			wake_up(tsk->wait_recv);
			log(DEBUG, "FIN received, reply ACK.");
			break;
		}
		break;
// --------------------------------------------------------------------
		case TCP_LAST_ACK:
		if(cb->flags & TCP_ACK)
		{
			tcp_update_window_safe(tsk, cb);
			tcp_update_send_buffer(tsk, cb->ack);
			tsk->state = TCP_CLOSED;
			log(DEBUG, "ACK received, connection closed.");
			tcp_bind_unhash(tsk);
			tcp_unhash(tsk);
		}
		break;
// --------------------------------------------------------------------
		case TCP_FIN_WAIT_1:
		process_data_packet(tsk, cb, packet);
		if((cb->flags & TCP_ACK) && cb->ack == tsk->snd_nxt)
		{
			tcp_update_window_safe(tsk, cb);
			tcp_update_send_buffer(tsk, cb->ack);
			tsk->state = TCP_FIN_WAIT_2;
			log(DEBUG, "ACK received, wait for FIN");
		}
		if((cb->flags & TCP_FIN) && cb->seq == tsk->rcv_nxt)
		{
			tsk->rcv_nxt = cb->seq_end;
			tcp_send_control_packet(tsk, TCP_ACK);
			tsk->state = TCP_CLOSING;
			log(DEBUG, "FIN received, reply ACK, wait ACK");
		}
		break;

		case TCP_FIN_WAIT_2:
		process_data_packet(tsk, cb, packet);
		if((cb->flags & TCP_FIN) && cb->seq == tsk->rcv_nxt)
		{
			tsk->rcv_nxt = cb->seq_end;
			tcp_send_control_packet(tsk, TCP_ACK);
			tsk->state = TCP_TIME_WAIT;
			//wait for 2 MSL before closed
			log(DEBUG, "FIN received, reply ACK, wait to be closed");
			tcp_set_timewait_timer(tsk);
		}
		break;

		case TCP_CLOSING:
		if((cb->flags & TCP_ACK) && cb->ack == tsk->snd_nxt)
		{
			tcp_update_window_safe(tsk, cb);
			tcp_update_send_buffer(tsk, cb->ack);

			tsk->state = TCP_TIME_WAIT;
			//wait for 2 MSL before closed
			log(DEBUG, "FIN received, reply ACK, wait to be closed");
			tcp_set_timewait_timer(tsk);
		}
// --------------------------------------------------------------------
		default:
			log(ERROR, "undefined socket status.");
			break;

	}
}
