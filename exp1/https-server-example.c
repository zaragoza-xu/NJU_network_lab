#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <resolv.h>
#include <fcntl.h>
#include <unistd.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

extern void *http_server(void *);
void handle_https_request(SSL* ssl)
{
    const char* response="HTTP/1.0 200 OK\r\n";
	const char* response_206="HTTP/1.0 206 Partial Content\r\n";
	const char* response_404="HTTP/1.0 404 Not Found\r\n";
    if (SSL_accept(ssl) == -1){
		perror("SSL_accept failed");
		exit(1);
	}

	char buf[1024] = {0}, method[16], uri[1024], ver[16], key[64];;
    int bytes = SSL_read(ssl, buf, sizeof(buf));
	int range = 0;
	size_t key_len, range_s, range_t = 0;
	if (bytes < 0) {
		perror("SSL_read failed");
		exit(1);
	}
	sscanf(buf, "%s /%s %s", method, uri, ver);
//	printf("%s\n", buf);

	char *line = strtok(buf, "\r\n");
//	printf("%p\n", line);
	
	while(line != NULL)
	{
		char *colon = strchr(line, ':');
		if(colon != NULL)
		{
			key_len = (size_t)(colon - line);
			strncpy(key, line, key_len);
			key[key_len] = '\0';
			if(strcmp(key, "Range") == 0)
			{
				range = 1;
				break;
			}
		}
		line = strtok(NULL, "\r\n");
		//printf("%s\n%zu\n", line, strlen(line));
//		printf("%s",buf);
//		fflush(stdout);
	}
	
	if(range)
	{
//		printf("line %zu key %s\n", strlen(line), key);
		char val[64];
		strncpy(val, line + key_len + 2, strlen(line) - key_len - 2);
		val[strlen(line) - key_len - 2] = '\0';
		char *dash = strchr(val, '-'), *eq = strchr(val, '=');
//		printf("%zu\n",strlen(val));
		*dash = '\0';
		range_s = atoi(eq + 1);
		if(*(dash + 1) != '\0')
		{
			range_t = atoi(dash + 1);
		}
//		printf("%s\nrange%zu %zu\n", val, range_s, range_t);
	}
	

	int fd = open(uri, O_RDONLY);
	struct stat file_stat;
	if(fd < 0)
	{
		SSL_write(ssl, response_404, strlen(response_404));
		
	}
	else
	{
		if(stat(uri, &file_stat) < 0)
		{
			perror("stat file failed");
			exit(1);
		}
		char header[1024], buf_file[1024];
		size_t file_size, len;
		file_size = file_stat.st_size;
		if(!range)
		{
			SSL_write(ssl, response, strlen(response));
			snprintf(header, sizeof(header), "Content-Length: %zu\r\n\r\n", file_size);
			SSL_write(ssl, header, strlen(header));
			while((len = read(fd, buf_file, sizeof(buf_file))) > 0)
			{
				SSL_write(ssl, buf_file, len);
			}
		}
		else
		{
			if(lseek(fd, range_s, SEEK_SET) < 0)
			{
				perror("lseek failed");
				exit(1);
			}
			SSL_write(ssl, response_206, strlen(response_206));
			if(range_t == 0)
				range_t = file_size;
			snprintf(header, sizeof(header), "Content-Range: bytes %zu-%zu/%zu\r\nContent-Length: %zu\r\n\r\n", range_s, range_t, file_size, range_t - range_s + 1);
			SSL_write(ssl, header, strlen(header));
//			printf("aaa\n");
			fflush(stdout);
			while((len = read(fd, buf_file, 1)) > 0 && lseek(fd, 0, SEEK_CUR) <= range_t + 1)
			{
				SSL_write(ssl, buf_file, 1);
			}
		}
	}

    int sock = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sock);
}

int main()
{
	// init SSL Library
	pthread_t thrd;
    pthread_create(&thrd, NULL, &http_server, NULL);
	
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	// enable TLS method
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);

	// load certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
		perror("load cert failed");
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
		perror("load prikey failed");
		exit(1);
	}

	// init socket, listening to port 443
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(443);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
		exit(1);
	}
//	printf("init https server\n");
//	fflush(stdout);
	listen(sock, 10);

	while (1) {
		struct sockaddr_in caddr;
		socklen_t len;
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
		SSL *ssl = SSL_new(ctx); 
		SSL_set_fd(ssl, csock);
//		printf("https request received\n");
//		fflush(stdout);
		handle_https_request(ssl);
	}

	close(sock);
	SSL_CTX_free(ctx);

	return 0;
}
