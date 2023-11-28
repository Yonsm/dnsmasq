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

#define _TCPDNS_LOG(text, ...) fprintf(stderr, "TCPDNS %d, " text "\n", thread->fd, ##__VA_ARGS__)
#define _TCPDNS_ERR(text) fprintf(stderr, "TCPDNS %d, %s errno=%d %s\n", thread->fd, text, errno, strerror(errno))

//#define _TCPDNS_REUSE_CONNECTION
#ifdef _TCPDNS_REUSE_CONNECTION
// TCPDNS server (per server)
typedef struct _TCPDNS_SOCKET
{
	int fd;						// Server socket
	union mysockaddr addr;		// Server address
	// char addrbuf[ADDRSTRLEN];	// Server address string buffer
	pthread_mutex_t working;		// Server is working on progress
	struct _TCPDNS_SOCKET *next; // Next TCP DNS server
	unsigned char connected;	// Server is connected
} *TCPDNS_SOCKET;

static TCPDNS_SOCKET _server = NULL;
static pthread_mutex_t _server_mutex = PTHREAD_MUTEX_INITIALIZER;

// Find out TCPDNS server for session
inline static TCPDNS_SOCKET tcpdns_socket(TCPDNS_THREAD *thread)
{
	pthread_mutex_lock(&_server_mutex);

	TCPDNS_SOCKET server = _server;
	for (; server; server = server->next)
	{
		if (sockaddr_isequal(&server->addr, &thread->session.serv))
		{
			//_LOG_DBG_SRV(server, "existed");
			break;
		}
	}

	if (server == NULL)
	{
		server = safe_malloc(sizeof(*server));
		server->fd = socket(thread->session.serv.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
		server->connected = 0;
		memcpy(&server->addr, &thread->session.serv, thread->session.nserv);
		//_LOG_DBG_SRV(server, "created");

		pthread_mutex_init(&server->working, NULL);
		server->next = _server;
		_server = server;
	}

	pthread_mutex_unlock(&_server_mutex);

	pthread_mutex_lock(&server->working);
	return server;
}

inline static int tcpdns_connect(TCPDNS_SOCKET server, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;
	if (server->connected)
		ret = 0;
	else if ((ret = connect(server->fd, addr, addrlen)) == 0)
		server->connected = 1;
	return ret;
}

inline static ssize_t tcpdns_send(TCPDNS_SOCKET server, void *buf, size_t len, int flags)
{
	return send(server->fd, buf, len, flags);
}

inline static ssize_t tcpdns_recv(TCPDNS_SOCKET server, void *buf, size_t len, int flags)
{
	return recv(server->fd, buf, len, flags);
}

inline static int tcpdns_shutdown(TCPDNS_SOCKET server, int how)
{
	server->connected = 0;
	return shutdown(server->fd, how);
}

inline static void tcpdns_reset(TCPDNS_SOCKET server, TCPDNS_THREAD *thread)
{
	close(server->fd);
	server->fd = socket(thread->session.serv.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
}

inline static int tcpdns_close(TCPDNS_SOCKET server)
{
	return pthread_mutex_unlock(&server->working);
}
#else
#define TCPDNS_SOCKET int
#define tcpdns_socket(thread) socket(thread->session.serv.sa.sa_family, SOCK_STREAM, IPPROTO_TCP)
#define tcpdns_connect connect
#define tcpdns_send send
#define tcpdns_recv recv
#define tcpdns_shutdown shutdown
#define tcpdns_reset(server, thread) close(server); server = tcpdns_socket(thread)
#define tcpdns_close close
#endif

// TCPDNS session worker
static void tcpdns_worker(TCPDNS_THREAD *thread)
{
	TCPDNS_SOCKET server = tcpdns_socket(thread);
	_TCPDNS_LOG("begin %d", (int)server);

	unsigned nreq = thread->session.nload;
	thread->session.nload = htons(nreq);
	nreq += 2;
	
	for (int i = 0; i < 3; i++)
	{
		if (tcpdns_connect(server, &thread->session.serv.sa, thread->session.nserv) == 0)
		{
			if ((tcpdns_send(server, &thread->session.nload, nreq, 0) == nreq))
			{
				ssize_t nres = tcpdns_recv(server, &thread->session.nload, 2 + thread->nbuf, 0) - 2;
				if (nres > 0 && nres == htons(thread->session.nload))
				{
					thread->session.magic = 'TDNS';
					ssize_t nsend = sizeof(TCPDNS_SESSION) + nres;
					ssize_t nsent = 0;//sendto(thread->fd, &thread->session, nsend, 0, &thread->local.sa, thread->nlocal);
					_TCPDNS_LOG("sendto %d %d=>%d", (int)thread->local.in.sin_port, (int)nsend, (int)nsent);
				}
				else
				{
					// break since buf maybe modified
					_TCPDNS_ERR("recv");
				}
				break;
			}
			_TCPDNS_ERR("send");
			tcpdns_shutdown(server, SHUT_RDWR);
		}
		else
		{
			_TCPDNS_ERR("connect");
		}
		sleep(1);
		tcpdns_reset(server, thread);
	}

	_TCPDNS_LOG("ended %d", (int)server);
	tcpdns_close(server);

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
