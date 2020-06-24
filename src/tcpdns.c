#include "dnsmasq.h"
#include <pthread.h>

// TCPDNS session (per query)
typedef struct _TCPDNS_SESSION {
	int fd; // Original UDP socket to server (but skip sendto by us)
	size_t len; // UDP DNS payload length
	socklen_t tolen; // Server address length
	union mysockaddr to; // Server address
	unsigned short request; // TCPDNS request = length + DNS payload
	unsigned char reqbuf[]; // DNS request payload
	//unsigned short response; // TCPDNS response
	//unsigned char resbuf[]; // DNS response payload
} TCPDNS_SESSION;

#define _LOG_ERR_SRV(server, ext, ...) _LOG_SRV(_LOG_ERR, server, ext, ##__VA_ARGS__)
#define _LOG_DBG_SRV(server, ext, ...) _LOG_SRV(_LOG_DBG, server, ext, ##__VA_ARGS__)
#ifdef _TCPDNS_REUSE_CONNECTION // NOT WOKING NOW
#define _LOG_SRV(logger, server, ext, ...) logger("TCPDNS %s:%d@%d, " ext, server->addrbuf, prettyprint_addr(&server->addr, server->addrbuf), server->fd, ##__VA_ARGS__)
// TCPDNS server (per server)
typedef struct TCPDNS_SERVER
{
	int fd; // Server socket
	int connected; // Server is connected
	union mysockaddr addr; // Server address
	char addrbuf[ADDRSTRLEN]; // Server address string buffer
	pthread_mutex_t doing; // Server is working on progress
	struct TCPDNS_SERVER *next; // Next TCP DNS server
} *TCPDNS_SOCKET;

static TCPDNS_SOCKET _server = NULL;
static pthread_mutex_t _server_mutex = PTHREAD_MUTEX_INITIALIZER;

// Find out TCPDNS server for session
inline static TCPDNS_SOCKET tcpdns_socket(TCPDNS_SESSION *session)
{
	pthread_mutex_lock(&_server_mutex);

	TCPDNS_SOCKET server = _server;
	for (; server; server = server->next) {
		if (sockaddr_isequal(&server->addr, &session->to)) {
			_LOG_DBG_SRV(server, "existed");
			break;
		}
	}

	if (server == NULL) {
		server = safe_malloc(sizeof(*server));
		server->fd = socket(session->to.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
		server->connected = 0;
		memcpy(&server->addr, &session->to, session->tolen);
		_LOG_DBG_SRV(server, "created");

		pthread_mutex_init(&server->doing, NULL);
		server->next = _server;
		_server = server;
	}

	pthread_mutex_unlock(&_server_mutex);

	pthread_mutex_lock(&server->doing);
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

inline static void tcpdns_reinit(TCPDNS_SOCKET server)
{
	close(server->fd);
	server->fd = socket(server->addr.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
}

inline static int tcpdns_close(TCPDNS_SOCKET server)
{
	return pthread_mutex_unlock(&server->doing);
}
#else
#define _LOG_SRV(logger, server, ext, ...) logger("TCPDNS %d, " ext, server, ##__VA_ARGS__)
#define TCPDNS_SOCKET int
#define tcpdns_socket(session) socket(session->to.sa.sa_family, SOCK_STREAM, IPPROTO_TCP)
#define tcpdns_connect connect
#define tcpdns_send send
#define tcpdns_recv recv
#define tcpdns_shutdown shutdown
#define tcpdns_reinit(server) ((void)0)
#define tcpdns_close close
#endif

// TCPDNS session worker
static void tcpdns_worker(TCPDNS_SESSION *session)
{
	session->request = htons(session->len);
	unsigned short *response = (unsigned short *)(session->reqbuf + session->len);

	TCPDNS_SOCKET server = tcpdns_socket(session);
	_LOG_DBG_SRV(server, "WORKING");

	for (int i = 0; i < 3; i++) {
		if (tcpdns_connect(server, &session->to.sa, session->tolen) ==0 ) {
			ssize_t nsend = session->len + 2;
			int success = tcpdns_send(server, &session->request, nsend, 0) == nsend;
			if (success) {
				ssize_t nrecv = tcpdns_recv(server, response, 2 + daemon->packet_buff_sz, 0);
				success = (nrecv - 2 == htons(*response));
				if (success) {
					union mysockaddr loopback;
					socklen_t looplen = sizeof(loopback);
					getsockname(session->fd, &loopback.sa, &looplen);
					ssize_t nsendto = sendto(session->fd, &response[1], nrecv - 2, 0, &loopback.sa, looplen);
					_LOG_DBG_SRV(server, "sendto=%ld", nsendto);
					break;
				} else {
					_LOG_ERR_SRV(server, "recv=%ld, errno=%d~%s", nrecv, errno, strerror(errno));
				}
			} else {
				_LOG_ERR_SRV(server, "send=%ld", nsend);
			}
			tcpdns_shutdown(server, SHUT_RDWR);
			_LOG_DBG_SRV(server, "shutdown");
		} else {
			_LOG_ERR_SRV(server, "connect errno=%d~%s", errno, strerror(errno));
			tcpdns_reinit(server);
		}
		sleep(1);
	}

	_LOG_DBG_SRV(server, "IDLING");
	tcpdns_close(server);

	free(session);
	pthread_detach(pthread_self());
	//pthread_exit(NULL);
}

// Send to TCPDNS (instead of UDPDNS)
ssize_t tcpdns_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen)
{
	flags = 0; // unused

	TCPDNS_SESSION *session = safe_malloc(sizeof(TCPDNS_SESSION) - sizeof(struct sockaddr) + tolen + 2 + len + 2 + daemon->packet_buff_sz);
	session->fd = fd;
	session->len = len;
	session->tolen = tolen;
	memcpy(&session->to, to, tolen);
	memcpy(session->reqbuf, buf, len);

	pthread_t tid;
	return pthread_create(&tid, NULL, (void *(*)(void *))tcpdns_worker, session) ? -1 : len;
}
