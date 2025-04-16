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

	FILE *file;
	if((file = fopen("server-output.dat", "w")) == NULL)
	{
		log(ERROR, "open output file failed.");
		exit(1);
	}

	int len;
	char buf[TCP_MSS + 10];
	while(tcp_sock_read(csk, buf, TCP_MSS) > 0)
	{
		fputs(buf, file);
		fflush(file);
		printf("%s", buf);
		memset(buf, 0, sizeof(buf));
	}

	//sleep(5);
	
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

	FILE *file;
	if((file = fopen("client-input.dat", "r")) == NULL)
	{
		log(ERROR, "open input file failed.");
		exit(1);
	}

	int len;
	char buf[TCP_MSS];
	while((len = fread(buf, sizeof(char), TCP_MSS, file)) > 0)
	{
		//buf[TCP_MSS - 1] = '\0';

		tcp_sock_write(tsk, buf, len);
		
	}

	tcp_sock_close(tsk);

	return NULL;
}
