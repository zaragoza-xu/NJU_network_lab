#include "tcp.h"
#include "tcp_sock.h"
#include "ip.h"
#include "ether.h"

#include "log.h"
#include "list.h"

#include <stdlib.h>
#include <string.h>

// initialize tcp header according to the arguments
void tcp_init_hdr(struct tcphdr *tcp, u16 sport, u16 dport, u32 seq, u32 ack,
		u8 flags, u16 rwnd)
{
	memset((char *)tcp, 0, TCP_BASE_HDR_SIZE);

	tcp->sport = htons(sport);
	tcp->dport = htons(dport);
	tcp->seq = htonl(seq);
	tcp->ack = htonl(ack);
	tcp->off = TCP_HDR_OFFSET;
	tcp->flags = flags;
	tcp->rwnd = htons(rwnd);
}

/*
创建send_buffer_entry加入send_buf尾部

注意上锁，后面不再强调。
*/
void tcp_send_buffer_add_packet(struct tcp_sock *tsk, char *packet, int len)
{
	log(DEBUG, "add: attempt to acquire send_buf_lock");
	pthread_mutex_lock(&tsk->send_buf_lock);
	log(DEBUG, "add: send_buf_lock acquired");
	struct send_buf_entry *buf = malloc(sizeof(struct send_buf_entry) + len + 1);

	memcpy(buf->data, packet, len);
	buf->len = len;
	init_list_head(&buf->list);
	list_add_tail(&buf->list, &tsk->send_buf);

	pthread_mutex_unlock(&tsk->send_buf_lock);
	log(DEBUG, "add: send_buf_lock released");

	tcp_set_retrans_timer(tsk);
}

/*
基于收到的ACK包，遍历发送队列，将已经接收的数据包从队列中移除

提取报文的tcp头可以使用packet_to_tcp_hdr，注意报文中的字段是大端序
return -1 on error, 0 on normal
*/
int tcp_update_send_buffer(struct tcp_sock *tsk, u32 ack)
{
	log(DEBUG, "update: attempt to acquire send_buf_lock");
	pthread_mutex_lock(&tsk->send_buf_lock);
	log(DEBUG, "update: send_buf_lock acquired");
	struct send_buf_entry *pos, *q;
	log(DEBUG, "empty %d", list_empty(&tsk->send_buf));
	list_for_each_entry_safe(pos, q, &tsk->send_buf, list)
	{
		u32 packet_seq = ntohl(packet_to_tcp_hdr(pos->data)->seq);
		log(DEBUG, "packet seq %d, cur ack %d", packet_seq, ack);
		if(packet_seq <= ack)
		{
			list_delete_entry(&pos->list);
			free(pos);
		}
		else
			break;
	}
	pthread_mutex_unlock(&tsk->send_buf_lock);
	log(DEBUG, "update: send_buf_lock released");

	tcp_update_retrans_timer(tsk);
	return 0;
}

/*
获取重传队列第一个包，修改ack号和checksum并通过ip_send_packet发送。

注意不要更新snd_nxt之类的参数，这是一个独立的重传报文。ip_send_packet会释放传入的指针，因而需要拷贝需要重传的报文。
return -1 on error, 0 on normal
*/
int tcp_retrans_send_buffer(struct tcp_sock *tsk)
{
	log(DEBUG, "retrans: attempt to acquire send_buf_lock");
	pthread_mutex_lock(&tsk->send_buf_lock);
	log(DEBUG, "retrans: send_buf_lock acquired");
	struct send_buf_entry *buf;
	if(list_empty(&tsk->send_buf))
	{
		pthread_mutex_unlock(&tsk->send_buf_lock);
		log(DEBUG, "retrans: send_buf_lock released");
		return -1;
	}
		

	buf = list_entry(tsk->send_buf.next, struct send_buf_entry, list);

	struct send_buf_entry *packet = malloc(sizeof(struct send_buf_entry) + buf->len + 1);
	log(DEBUG, "retrans: malloc succeed");
	memcpy(packet, buf, sizeof(*packet));

	struct iphdr *ip = packet_to_ip_hdr(packet->data);
	struct tcphdr *tcp = packet_to_tcp_hdr(packet->data);
	tcp->ack = htonl(tsk->rcv_nxt);
	tcp->rwnd = htons(tsk->rcv_wnd);

	tcp->checksum = tcp_checksum(ip, tcp);
	log(DEBUG, "retrans: retrans packet %d", tcp->seq);
	ip_send_packet(packet->data, packet->len);

	pthread_mutex_unlock(&tsk->send_buf_lock);
	log(DEBUG, "retrans: send_buf_lock released");
	return 0;
}

// send a tcp packet
//
// Given that the payload of the tcp packet has been filled, initialize the tcp 
// header and ip header (remember to set the checksum in both header), and emit 
// the packet by calling ip_send_packet.
void tcp_send_packet(struct tcp_sock *tsk, char *packet, int len) 
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	int ip_tot_len = len - ETHER_HDR_SIZE;
	int tcp_data_len = ip_tot_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;

	u32 saddr = tsk->sk_sip;
	u32	daddr = tsk->sk_dip;
	u16 sport = tsk->sk_sport;
	u16 dport = tsk->sk_dport;

	u32 seq = tsk->snd_nxt;
	u32 ack = tsk->rcv_nxt;
	u16 rwnd = tsk->rcv_wnd;

	tcp_init_hdr(tcp, sport, dport, seq, ack, TCP_PSH|TCP_ACK, rwnd);
	ip_init_hdr(ip, saddr, daddr, ip_tot_len, IPPROTO_TCP); 

	tcp->checksum = tcp_checksum(ip, tcp);

	ip->checksum = ip_checksum(ip);

	tsk->snd_nxt += tcp_data_len;

	ip_send_packet(packet, len);

	log(DEBUG, "add packet %d", seq);
	tcp_send_buffer_add_packet(tsk, packet, len);

}

// send a tcp control packet
//
// The control packet is like TCP_ACK, TCP_SYN, TCP_FIN (excluding TCP_RST).
// All these packets do not have payload and the only difference among these is 
// the flags.
void tcp_send_control_packet(struct tcp_sock *tsk, u8 flags)
{
	int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	char *packet = malloc(pkt_size);

	memset(packet, 0, pkt_size);
	if (!packet) {
		log(ERROR, "malloc tcp control packet failed.");
		return ;
	}
	else
	{
		struct iphdr *ip = packet_to_ip_hdr(packet);
		struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

		u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;

		ip_init_hdr(ip, tsk->sk_sip, tsk->sk_dip, tot_len, IPPROTO_TCP);
		tcp_init_hdr(tcp, tsk->sk_sport, tsk->sk_dport, tsk->snd_nxt, tsk->rcv_nxt, flags, tsk->rcv_wnd);

		tcp->checksum = tcp_checksum(ip, tcp);
		
		ip_send_packet(packet, pkt_size);

		if (flags & (TCP_SYN|TCP_FIN))
		{
			tsk->snd_nxt += 1;
			tcp_send_buffer_add_packet(tsk, packet, 1);
		}
	}
}

// send tcp reset packet
//
// Different from tcp_send_control_packet, the fields of reset packet is 
// from tcp_cb instead of tcp_sock.
void tcp_send_reset(struct tcp_cb *cb)
{
	int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	char *packet = malloc(pkt_size);
	if (!packet) {
		log(ERROR, "malloc tcp control packet failed.");
		return ;
	}
	else
	{
		struct iphdr *ip = packet_to_ip_hdr(packet);
		struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

		u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
		ip_init_hdr(ip, cb->daddr, cb->saddr, tot_len, IPPROTO_TCP);
		tcp_init_hdr(tcp, cb->dport, cb->sport, 0, cb->seq_end, TCP_RST|TCP_ACK, 0);
		tcp->checksum = tcp_checksum(ip, tcp);

		ip_send_packet(packet, pkt_size);
	}
	
}
