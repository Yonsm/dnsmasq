#include "dnsmasq.h"
#include "tcpdns.h"
#include <pthread.h>

typedef struct _TCPDNS_THREAD
{
	int fd;
	int nbuf;
	socklen_t nlocal;
	union mysockaddr local;
	TCPDNS_SESSION session;
} TCPDNS_THREAD;

#define _TCPDNS_LOG(text, ...) ((void)0) // fprintf(stderr, "TCPDNS %d, " text "\n", thread->fd, ##__VA_ARGS__)
#define _TCPDNS_ERR(text) ((void)0)		 // fprintf(stderr, "TCPDNS %d, %s errno=%d %s\n", thread->fd, text, errno, strerror(errno))

// TCPDNS session worker
static void tcpdns_worker(TCPDNS_THREAD *thread)
{
	unsigned nreq = thread->session.nload;
	thread->session.nload = htons(nreq);
	nreq += 2;

	int server = socket(thread->session.serv.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
	_TCPDNS_LOG("begin %d", (int)server);

	if (connect(server, &thread->session.serv.sa, thread->session.nserv) == 0)
	{
		if ((send(server, &thread->session.nload, nreq, 0) == nreq))
		{
			ssize_t nres = recv(server, &thread->session.nload, 2 + thread->nbuf, 0) - 2;
			if (nres > 0 && nres == htons(thread->session.nload))
			{
				thread->session.magic = 'TDNS';
				ssize_t nsend = sizeof(TCPDNS_SESSION) + nres;
				ssize_t nsent = sendto(thread->fd, &thread->session, nsend, 0, &thread->local.sa, thread->nlocal);
				_TCPDNS_LOG("sendto %d %d=>%d", (int)thread->local.in.sin_port, (int)nsend, (int)nsent);
			}
			else
				_TCPDNS_ERR("recv");
		}
		else
			_TCPDNS_ERR("send");
		shutdown(server, SHUT_RDWR);
	}
	else
		_TCPDNS_ERR("send");

	_TCPDNS_LOG("ended %d", (int)server);
	close(server);

	free(thread);
	pthread_detach(pthread_self());
}

// Send to TCPDNS
ssize_t tcpdns_sendto(int fd, const void *buf, size_t len, int flags __attribute__((unused)), const struct sockaddr *to, socklen_t tolen)
{
	size_t nbuf = daemon->packet_buff_sz;
	if (nbuf < len)
		nbuf = len;
	TCPDNS_THREAD *thread = safe_malloc(sizeof(TCPDNS_THREAD) + nbuf);
	thread->fd = fd;
	thread->nbuf = nbuf;

	int ret = getsockname(fd, &thread->local.sa, &thread->nlocal);
	if (ret == 0 && thread->local.in.sin_port == 0)
	{
		ret = bind(fd, &thread->local.sa, thread->nlocal);
		_TCPDNS_LOG("bind=%d", ret);
		if (ret == 0)
			ret = getsockname(fd, &thread->local.sa, &thread->nlocal);
	}
	if (ret != 0)
	{
		_TCPDNS_ERR("getsockname");
		free(thread);
		return ret;
	}

	thread->session.nserv = tolen;
	memcpy(&thread->session.serv, to, tolen);
	thread->session.nload = len;
	memcpy(&thread->session.nload + 1, buf, len);

	pthread_t tid;
	return pthread_create(&tid, NULL, (void *(*)(void *))tcpdns_worker, thread) ? -1 : len;
}
