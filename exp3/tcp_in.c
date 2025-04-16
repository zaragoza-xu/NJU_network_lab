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
				tcp_update_window_safe(tsk, cb);
				tcp_sock_accept_enqueue(child_tsk);
				child_tsk->state = TCP_ESTABLISHED;
				tcp_hash(child_tsk);
				init_list_head(&child_tsk->bind_hash_list);

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
		if(cb->flags | TCP_ACK && cb->flags | TCP_SYN)
		{
			tcp_update_window_safe(tsk, cb);
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
		if(cb->flags & TCP_ACK)
		{
			tcp_update_window_safe(tsk, cb);
		}
		if(is_tcp_seq_valid(tsk, cb) != 0 && cb->pl_len > 0)
		{
			tsk->rcv_wnd -= cb->pl_len;
			tsk->rcv_nxt = cb->seq_end;
			assert(tsk->rcv_wnd >= 0);

			log(DEBUG, "tcp_process write: attempt to acquire rcv_buf_lock %p", tsk);
			pthread_mutex_lock(&tsk->rcv_buf_lock);
			log(DEBUG, "tcp_process write: rcv_buf_lock acquired");

			write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
			//puts(cb->payload);
			tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
			
			pthread_mutex_unlock(&tsk->rcv_buf_lock);
			log(DEBUG, "tcp_process write: rcv_buf_lock released");

			log(DEBUG, "received a packet");
			
			tcp_send_control_packet(tsk, TCP_ACK);
			wake_up(tsk->wait_recv);
		}
		if(cb->flags & TCP_FIN)
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
			tsk->state = TCP_CLOSED;
			log(DEBUG, "ACK received, connection closed.");
			tcp_unhash(tsk);
		}
		break;
// --------------------------------------------------------------------
		case TCP_FIN_WAIT_1:
		if(cb->flags & TCP_ACK)
		{
			tcp_update_window_safe(tsk, cb);
			tsk->state = TCP_FIN_WAIT_2;
			log(DEBUG, "ACK received, wait for FIN");
		}
		// no break, in case for FIN | ACK.

		case TCP_FIN_WAIT_2:
		if(cb->flags & TCP_FIN)
		{
			tsk->rcv_nxt = cb->seq_end;
			tcp_send_control_packet(tsk, TCP_ACK);
			tsk->state = TCP_TIME_WAIT;
			//wait for 2 MSL before closed
			log(DEBUG, "FIN received, reply ACK, wait to be closed");
			tcp_set_timewait_timer(tsk);
		}
		break;
// --------------------------------------------------------------------
		default:
			log(ERROR, "undefined socket status.");
			break;

	}


}
