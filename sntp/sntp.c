/*- Project:    A simple SNTP client
  - Author:     Richard James Howe
  - License:    The Unlicense
  - Email:      howe.r.j.89@gmail.com
  - Repository: https://github.com/howerj/sntp */
#include "sntp.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DELTA (2208988800ull)

static inline unsigned long unpack32(unsigned char *p) {
	assert(p);
	unsigned long l = 0;
	l |= ((unsigned long)p[0]) << 24;
	l |= ((unsigned long)p[1]) << 16;
	l |= ((unsigned long)p[2]) <<  8;
	l |= ((unsigned long)p[3]) <<  0;
	return l;
}

static inline void *get_in_addr(struct sockaddr *sa) { /* see https://beej.us/guide/bgnet/html/#cb46-22 */
	assert(sa);
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static inline char *itoa(char a[32], unsigned n) {
	assert(a);
	int i = 0;
	do a[i++] = "0123456789"[n % 10]; while(n /= 10);
	a[i] = '\0';
	for (int j = 0; j < (i/2); j++) {
		char t = a[j];
		a[j] = a[(i - j) - 1];
		a[(i - j) - 1] = t;
	}
	return a;
}

static int establish(const char *host_or_ip, unsigned port, int type) {
	assert(host_or_ip);
	int fd = -1;
	struct addrinfo *servinfo = NULL, *p = NULL;
       	struct addrinfo hints = { .ai_family   = AF_UNSPEC, .ai_socktype = type, };
	if (port == 0 || port > 65535 || (type != SOCK_DGRAM && type != SOCK_STREAM))
		return -1;
	if (getaddrinfo(host_or_ip, itoa((char[32]){0}, port) , &hints, &servinfo) != 0)
		goto fail;

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
			continue;
		if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
			if (close(fd) < 0)
				goto fail;
			fd = -1;
			continue;
		}
		break;
	}
	if (p == NULL)
		goto fail;

	char ip[INET6_ADDRSTRLEN] = { 0 };
	if (NULL == inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), ip, sizeof ip))
		goto fail;

	freeaddrinfo(servinfo);
	servinfo = NULL;

	struct timeval tx_tv = { .tv_sec = 30 }, rx_tv = { .tv_sec = 30 };
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tx_tv, sizeof tx_tv) < 0)
		goto fail;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rx_tv, sizeof rx_tv) < 0)
		goto fail;

	return fd;
fail:
	(void)close(fd);
	if (servinfo) {
		freeaddrinfo(servinfo);
		servinfo = NULL;
	}
	return -1;
}

int sntp(const char *server, unsigned port, unsigned long *seconds, unsigned long *fractional) {
	assert(server);
	assert(seconds);
	assert(fractional);
	/* we could populate some fields in 'h' with seconds/fractional before sending...*/
	*seconds = 0; 
	*fractional = 0;
	unsigned char h[48] = { 0x1b, };
	/* we could make this stateful and non-blocking if needed */
	const int fd = establish(server, port ? port : 123, SOCK_DGRAM);
	if (fd < 0)
		return -1;
	if (write(fd, h, sizeof h) != sizeof h)
		return -2;
	if (read(fd, h, sizeof h) != sizeof h)
		return -3;
	if (close(fd) < 0)
		return -4;
	*seconds    = unpack32(&h[40]) - DELTA;
	*fractional = unpack32(&h[44]);
	return 0;
}

