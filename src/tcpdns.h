
#pragma pack(push, 1)
typedef struct _TCPDNS_SESSION
{
	unsigned int magic;
	socklen_t nserv;
	union mysockaddr serv;
	unsigned short nload;
	//unsigned char payload[];
} TCPDNS_SESSION;
#pragma pack(pop)

ssize_t tcpdns_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);

// inline static void *tcpdns_parse(TCPDNS_SESSION *session, ssize_t *n, union mysockaddr *serveraddr, socklen_t *addrlen)
// {
// 	if (session->magic == 'TDNS')
// 	{
// 		*n = *n - sizeof(TCPDNS_SESSION);
// 		*addrlen = session->nserv;
// 		memcpy(serveraddr, &session->serv, *addrlen);
// 		return &session->nload + 1;
// 	}
// 	return session;
// }
