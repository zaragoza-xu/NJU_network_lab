#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	while(1)
	{
		char data[100] = {0};
		if(tcp_sock_read(csk, data, 62) <= 0)
			break;
		char new_data[100] = "server echoes: ";
		strcat(new_data, data);
		if(tcp_sock_write(csk, new_data, strlen(new_data)) <= 0)
			break;
	}

	sleep(5);

	tcp_sock_close(csk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	const char data[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const u32 data_len = 62;
	for(int i = 0; i < 6; i ++)
	{
		char new_data[100] = {0};
		strncpy(new_data, data + i, data_len - i);
		strncat(new_data, data, i);
		tcp_sock_write(tsk, new_data, data_len);
		if(tcp_sock_read(tsk, new_data, 100) <= 0)
			break;
		printf("%s\n", new_data);
	}

	tcp_sock_close(tsk);

	return NULL;
}
