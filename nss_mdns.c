/*-
 * Copyright (c) 2013 Rui Paulo <rpaulo@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/route.h>
#include <nsswitch.h>

#define	DEBUG
#ifdef DEBUG
#define	MDNS_DEBUG(_msg, ...)	syslog(LOG_DEBUG, "nss_mdns: " _msg, \
				    ## __VA_ARGS__)
#else
#define	MDNS_DEBUG(_msg, ...)	
#endif

enum mdns_resptype {
	MDNS_RESP_AVAHI = 1,
	MDNS_RESP_MDNSD = 2	/* mDNSResponder */
};

struct mdns_handle {
	int s;
	int af;
	enum mdns_resptype resptype;
	enum {
		MDNS_REQ_NAME,
		MDNS_REQ_ADDR
	} reqtype;
};

struct mdns_result {
	char	name[64];
	int	ifindex;
	union {
		in_addr_t v4;
		struct in6_addr v6;
	} addr;
};

static int	mdns_matches_local(const char *);
static int	mdns_matches_addr(int, void *);
static int 	mdns_issue_name_query(int, const char *, struct mdns_handle *);
static int	mdns_issue_addr_query(int, const void *, struct mdns_handle *);
static int	mdns_parse_result(struct mdns_handle *, struct mdns_result *);

ns_mtab *	nss_module_register(const char *, unsigned int *,
		    nss_module_unregister_fn *);

static NSS_METHOD_PROTOTYPE(mdns_getaddrinfo);
static NSS_METHOD_PROTOTYPE(mdns_gethostbyaddr_r);
static NSS_METHOD_PROTOTYPE(mdns_gethostbyname2_r);

static ns_mtab ns_methods[] = {
	{ NSDB_HOSTS, "getaddrinfo", mdns_getaddrinfo, NULL },
	{ NSDB_HOSTS, "gethostbyaddr_r", mdns_gethostbyaddr_r, NULL },
	{ NSDB_HOSTS, "gethostbyname2_r", mdns_gethostbyname2_r, NULL },
};

ns_mtab *
nss_module_register(const char *src __unused, unsigned int *mtabsize,
    nss_module_unregister_fn *f)
{

	*mtabsize = sizeof(ns_methods) / sizeof(*ns_methods);
	*f = NULL;

	return (ns_methods);
}

static struct addrinfo *
ai_fill(int family, struct addrinfo *oai, struct mdns_result *md_res)
{
	struct addrinfo *ai;
	struct sockaddr_storage *ss;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	size_t len;

	ai = malloc(sizeof(*ai) + sizeof(struct sockaddr_storage));
	if (ai == NULL)
		return (NULL);
	ai->ai_flags = oai->ai_flags;
	/* N.B.: oai->ai_family might have been PF_UNSPEC. */
	ai->ai_family = family;
	ai->ai_socktype = oai->ai_socktype;
	ai->ai_protocol = oai->ai_protocol;
	/* N.B.: ai_addrlen set below */
	ai->ai_addr = (struct sockaddr *)(ai + 1);
	ss = (struct sockaddr_storage *)ai->ai_addr;
	bzero(ss, sizeof(*ss));
	ss->ss_family = ai->ai_family;
	len = strlen(md_res->name) + 1;
	ai->ai_canonname = malloc(len);
	if (ai->ai_canonname == NULL) {
		free(ai);
		return (NULL);
	}
	strlcpy(ai->ai_canonname, md_res->name, len);
	ai->ai_next = NULL;
	switch (ss->ss_family) {
	case AF_INET:
		ai->ai_addrlen = sizeof(*sin);
		ss->ss_len = ai->ai_addrlen;
		sin = (struct sockaddr_in *)ss;
		memcpy(&sin->sin_addr, &md_res->addr,
		    sizeof(in_addr_t));
		break;
	case AF_INET6:
		ai->ai_addrlen = sizeof(*sin6);
		ss->ss_len = ai->ai_addrlen;
		sin6 = (struct sockaddr_in6 *)ss;
		memcpy(&sin6->sin6_addr, &md_res->addr,
		    sizeof(struct in6_addr));
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
			sin6->sin6_scope_id = md_res->ifindex;
		break;
	}

	return (ai);
}

/*
 * We only need to handle the FQDN lookup because the NSS API will handle
 * numeric addresses, ports, flags, etc.
 */
static int
mdns_getaddrinfo(void *ret, void *data __unused, va_list ap)
{
	const char *name;
	struct mdns_handle md_handle;
	struct mdns_result md_res;
	struct addrinfo *v4ai = NULL, *v6ai = NULL, *oai, **retp;

	/*
	 * Parse and validate the arguments.
	 */
	name = va_arg(ap, const char *);
	if (!mdns_matches_local(name))
		return (NS_UNAVAIL);
	oai = va_arg(ap, struct addrinfo *);
	if (oai->ai_family != AF_UNSPEC &&
	    oai->ai_family != AF_INET && 
	    oai->ai_family != AF_INET6)
		return (NS_UNAVAIL);
	retp = (struct addrinfo **)ret;
	*retp   = NULL;

	/*
	 * In the getaddrinfo() case, we are not passed any buffer (see
	 * below).  We will allocate space for addrinfo and ai_canonname which
	 * will later be freed by freeaddrinfo().
	 */
	if (oai->ai_family == AF_INET6 || oai->ai_family == AF_UNSPEC) {
		if (mdns_issue_name_query(AF_INET6, name, &md_handle) >= 0 &&
		    mdns_parse_result(&md_handle, &md_res) == 0)
			v6ai = ai_fill(AF_INET6, oai, &md_res);
	}
	if (oai->ai_family == AF_INET || oai->ai_family == AF_UNSPEC) {
		if (mdns_issue_name_query(AF_INET, name, &md_handle) >= 0 &&
		    mdns_parse_result(&md_handle, &md_res) == 0)
			v4ai = ai_fill(AF_INET, oai, &md_res);
	}

	if (v6ai) {
		*retp = v6ai;
		if (v4ai)
			v6ai->ai_next = v4ai;
	} else if (v4ai)
		*retp = v4ai;

	if (*retp)
		return (NS_SUCCESS);
	else
		return (NS_NOTFOUND);
}

static int
mdns_gethostbyaddr_r(void *ret, void *data __unused, va_list ap)
{
	void *addr;
	socklen_t len;
	int af, error, *h_error;
	struct hostent *he;
	char *buf;
	size_t buflen;
	struct hostent **retp;
	struct mdns_handle md_handle;
	struct mdns_result md_res;

	/*
	 * Parse and validate the arguments.
	 */
	addr = va_arg(ap, void *);
	len = va_arg(ap, socklen_t);
	af = va_arg(ap, int);
	if (af != AF_INET && af != AF_INET6)
		return (NS_UNAVAIL);
	if (!mdns_matches_addr(af, addr))
		return (NS_UNAVAIL);
	he = va_arg(ap, struct hostent *);
	if (he == NULL)
		return (NS_UNAVAIL);
	buf = va_arg(ap, char *);
	buflen = va_arg(ap, size_t);
	error = va_arg(ap, int);
	h_error = va_arg(ap, int *);

	retp = (struct hostent **)ret;
	*retp   = NULL;

	if (mdns_issue_addr_query(af, addr, &md_handle) < 0)
		return (NS_UNAVAIL);
	if (mdns_parse_result(&md_handle, &md_res) == 0) {
		/*
		 * We were given a buffer (buf) to hold the data. This is how
		 * it looks like in memory:
		 *
		 * buf                  hostent
		 * -------------------
		 * | md_res.name[0]  | <- h_name
		 * | md_res.name[1]  |
		 * | ...             |
		 * | NUL             |
		 * | NULL            | <- h_aliases
		 * | addr[0]         |
		 * | addr[1]         |
		 * | ...             |
		 * | ptr to addr[0]  | <- h_addr_list
		 * | NULL            |
		 * |------------------
		 */
		if (strlen(md_res.name) + 1 + sizeof(void *) + 
		    len + 2 * sizeof(void *) > buflen)
			return (NS_UNAVAIL);
		he->h_addrtype = af;
		he->h_length = len;
		strlcpy(buf, md_res.name, strlen(md_res.name) + 1);
		he->h_name = buf;
		buf += strlen(md_res.name) + 1;

		bzero(buf, sizeof(void *));
		he->h_aliases = (char **)buf;
		buf += sizeof(void *);

		memcpy(buf, addr, he->h_length);
		buf += he->h_length;
		he->h_addr_list = (char **)buf;
		he->h_addr_list[0] = (buf - he->h_length);
		he->h_addr_list[1] = NULL;
		*h_error = 0;
		*retp = he;

		return (NS_SUCCESS);
	} else
		return (NS_UNAVAIL);
}

static int
mdns_gethostbyname2_r(void *ret, void *data __unused, va_list ap)
{
	const char *name;
	struct hostent *he;
	char *buf;
	size_t len;
	int af, error, *h_error;
	struct hostent **retp;
	struct mdns_handle md_handle;
	struct mdns_result md_res;

	/*
	 * Parse and validate the arguments.
	 */
	name = va_arg(ap, char *);
	if (!mdns_matches_local(name))
		return (NS_UNAVAIL);
	af = va_arg(ap, int);
	if (af != AF_INET && af != AF_INET6)
		return (NS_UNAVAIL);
	he = va_arg(ap, struct hostent *);
	if (he == NULL)
		return (NS_UNAVAIL);
	buf = va_arg(ap, char *);
	len = va_arg(ap, size_t);
	error = va_arg(ap, int);
	h_error = va_arg(ap, int *);

	retp = (struct hostent **)ret;
	*retp   = NULL;

	if (mdns_issue_name_query(af, name, &md_handle) < 0)
		return (NS_UNAVAIL);
	if (mdns_parse_result(&md_handle, &md_res) == 0) {
		/*
		 * We were given a buffer (buf) to hold the data. This is how
		 * it looks like in memory:
		 *
		 * buf                  hostent
		 * -------------------
		 * | md_res.name[0]  | <- h_name
		 * | md_res.name[1]  |
		 * | ...             |
		 * | NUL             |
		 * | NULL            | <- h_aliases
		 * | md_res.addr[0]  | [1]
		 * | md_res.addr[1]  |
		 * | ...             |
		 * | ptr to addr[0]  | <- h_addr_list
		 * | NULL            |
		 * |------------------
		 */
		he->h_addrtype = af;
		he->h_length = af == AF_INET ? sizeof(md_res.addr.v4) :
		    sizeof(md_res.addr.v6);

		if (strlen(md_res.name) + 1 + sizeof(void *) + 
		    he->h_length + 2 * sizeof(void *) > len)
			return (NS_UNAVAIL);

		strlcpy(buf, md_res.name, strlen(md_res.name) + 1);
		he->h_name = buf;
		buf += strlen(md_res.name) + 1;

		bzero(buf, sizeof(void *));
		he->h_aliases = (char **)buf;
		buf += sizeof(void *);

		memcpy(buf, &md_res.addr, he->h_length);
		buf += he->h_length;
		he->h_addr_list = (char **)buf;
		he->h_addr_list[0] = (buf - he->h_length);
		he->h_addr_list[1] = NULL;
		*h_error = 0;
		*retp = he;

		return (NS_SUCCESS);
	} else
		return (NS_NOTFOUND);


	return 0;
}

/*
 * Avahi hooks.
 *
 * When Avahi is running, there is a Unix socket living at AVAHI_PATH.
 * To resolve mDNS names, we connect to that Unix socket and issue one
 * command. Avahi only accepts 1 command at a time, so we need to connect
 * twice if we want to resolve IPv6 and IPv4.
 *
 * Here's the list of available commands:
 *
 * HELP
 * + Available commands are:
 * +      RESOLVE-HOSTNAME <hostname>
 * +      RESOLVE-HOSTNAME-IPV6 <hostname>
 * +      RESOLVE-HOSTNAME-IPV4 <hostname>
 * +      RESOLVE-ADDRESS <address>
 * +      BROWSE-DNS-SERVERS
 * +      BROWSE-DNS-SERVERS-IPV4
 * +      BROWSE-DNS-SERVERS-IPV6
 *
 * It's also worth noting that RESOLVE-HOSTNAME will pick IPv4 or IPv6 at
 * random which doesn't suit our purposes.
 */

#define	AVAHI_PATH	"/var/run/avahi-daemon/socket"

static int
avahi_connect(int s)
{
	struct sockaddr_un un;

	un.sun_family = AF_LOCAL;
	strlcpy(un.sun_path, AVAHI_PATH, sizeof(un.sun_path));
	un.sun_len = SUN_LEN(&un);
	
	return (connect(s, (struct sockaddr *)&un, sizeof(un)));
}

static void
avahi_issue_name_query(int s, int af, const char *name)
{
	char q[128];
	size_t len;

	len = snprintf(q, sizeof(q), "RESOLVE-HOSTNAME-IPV%c %s\n",
	    af == AF_INET ? '4' : '6', name);
	write(s, q, len);
}

static void
avahi_issue_addr_query(int s, const char *addr)
{
	char q[64];
	size_t len;
	
	len = snprintf(q, sizeof(q), "RESOLVE-ADDRESS %s\n", addr);
	write(s, q, len);
}

static int
avahi_read_reply(int s, char *buf, size_t buflen)
{
	fd_set fdset;
	struct timeval tv;

	FD_ZERO(&fdset);
	FD_SET(s, &fdset);
	tv.tv_usec = 0;
	tv.tv_sec = 10;
	if (select(s + 1, &fdset, NULL, NULL, &tv) <= 0) {
		MDNS_DEBUG("select timed out");
		return (-1);
	}

	if (read(s, buf, buflen) < 0) {
		MDNS_DEBUG("read failed");
		return (-1);
	}
	MDNS_DEBUG("reply: %s", buf);

	return (0);
}


static int
avahi_parse_name_result(struct mdns_handle *md_handle,
    struct mdns_result *md_res)
{
	char addr[64], buf[128];

	if (avahi_read_reply(md_handle->s, buf, sizeof(buf)) < 0)
		return (1);

	if (buf[0] == '+') {
		sscanf(buf, "%*c %d %*d %64s %64s", 
		    &md_res->ifindex, md_res->name,
		    addr);
		inet_pton(md_handle->af, addr, &md_res->addr);
		return (0);
	}

	return (1);

}

static int
avahi_parse_addr_result(struct mdns_handle *md_handle, struct mdns_result *md_res)
{
	char buf[128];

	if (avahi_read_reply(md_handle->s, buf, sizeof(buf)) < 0)
		return (1);

	if (buf[0] == '+') {
		sscanf(buf, "%*c %d %*d %64s", 
		    &md_res->ifindex, md_res->name);
		return (0);
	}

	return (1);

}

/*
 * mDNSResponder hooks.
 */
#define	MDNSD_PATH	"/var/run/mdnsd"

struct mdnsd_hdr {
	uint32_t ver;
	uint32_t len;
	uint32_t flags;
	uint32_t op;
	union {
		intptr_t ctx;
		uint32_t _ptr[2];
	} ctx; 
	uint32_t ridx;
} __packed;

static int
mdnsd_connect(int s)
{
	struct sockaddr_un un;

	un.sun_family = AF_LOCAL;
	strlcpy(un.sun_path, MDNSD_PATH, sizeof(un.sun_path));
	un.sun_len = SUN_LEN(&un);
	
	return (connect(s, (struct sockaddr *)&un, sizeof(un)));
}

static void
mdnsd_issue_name_query(int s, int af, const char *name)
{
	struct mdnsd_hdr *req;
	size_t mlen;
	char buf[1024], *p;
	uint32_t i;

	mlen = sizeof(uint32_t);	/* flags */
	mlen += sizeof(uint32_t);	/* interface index */
	mlen += sizeof(uint32_t);	/* protocol */
	mlen += strlen(name) + 1;

	bzero(&buf, sizeof(buf));
	req = (struct mdnsd_hdr *)buf;
	req->ver = htonl(1);
	req->len = htonl(mlen);
	req->op = htonl(15);	/* Addrinfo request */
	p = (char *)(req + 1);
	i = htonl(0x10);
	memcpy(p, &i, sizeof(i));
	p += sizeof(i);
	p += 4;
	i = htonl(af);
	memcpy(p, &i, sizeof(i));
	p += sizeof(i);;
	strcpy(p, name);
	p += strlen(name) + 1;

	write(s, buf, sizeof(*req) + mlen);
}

#if 0
static int
mdnsd_parse_name_result(struct mdns_handle *md_handle,
    struct mdns_result *md_res)
{


	return (0);
}

static int
mdnsd_parse_addr_result(struct mdns_handle *md_handle,
    struct mdns_result *md_res)
{
	return (0);
}
#endif

static int
mdns_matches_local(const char *name)
{
	static const char *domain = ".local";
	size_t dlen = 6;
	size_t len;

	len = strlen(name);
	if (len <= dlen)
		return (0);

	/* Also allow "local." */
	if (name[len-1] == '.')
		dlen++;

	return (strncasecmp(name + len - dlen, domain, 6) == 0);
}

static int
mdns_matches_addr(int af, void *addr)
{
	in_addr_t *v4 = NULL;
	struct in6_addr *v6 = NULL;
	int s, ret = 0, i;
	char buf[sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in6)];
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct rt_msghdr *rtm;
	size_t len;
	static int seq = 1;
	pid_t pid;

	/*
	 * Handle the fast path: we can determine the network segment where
	 * the node is by looking at the address type.
	 */
	if (af == AF_INET) {
		v4 = (in_addr_t *)addr;
		if (IN_LOOPBACK(ntohl(*v4)))
			return (0);
		if (IN_LINKLOCAL(ntohl(*v4)) || IN_PRIVATE(ntohl(*v4)))
			return (1);
	} else {
		v6 = (struct in6_addr *)addr;
		if (IN6_IS_ADDR_LOOPBACK(v6))
			return (0);
		if (IN6_IS_ADDR_LINKLOCAL(v6)) {
			/* 
			 * Check for fe80::1.
			 * N.B.: we can't perform a memcmp with "fe80::1"
			 * because the scope id might be embedded inside the
			 * address.
			 */
			for (i = 4; i < 14; i++)
				if (v6->s6_addr[i] != 0)
					break;
			if (i == 14 && v6->s6_addr[15] == 1) {
				MDNS_DEBUG("found fe80::1\n");
				return (0);
			} else 
				return (1);
		}
	}
	/*
	 * Otherwise, we have to consult the routing table.
	 */
	s = socket(PF_ROUTE, SOCK_RAW, af);
	if (s < 0)
		return (1);
	pid = getpid();
	bzero(&buf, sizeof(buf));
	rtm = (struct rt_msghdr *)buf;
	len = sizeof(*rtm);
	if (v6)
		len += sizeof(*sin6);
	else
		len += sizeof(*sin);
	rtm->rtm_msglen = len;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = RTM_GET;
	rtm->rtm_flags = RTF_UP|RTF_GATEWAY|RTF_HOST;
	rtm->rtm_addrs = RTA_DST;
	rtm->rtm_pid = pid;
	rtm->rtm_seq = seq;
	if (v6) {
		sin6 = (struct sockaddr_in6 *)(rtm + 1);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(*sin6);
		memcpy(&sin6->sin6_addr, v6, sizeof(*v6));
	} else {
		sin = (struct sockaddr_in *)(rtm + 1);
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		memcpy(&sin->sin_addr, v4, sizeof(*v4));
	}
	send(s, buf, len, 0);
	while (recv(s, buf, sizeof(buf), 0) > 0) {
		rtm = (struct rt_msghdr *)buf;
		/*
		 * A host is local if it doesn't go through any gateway.
		 */
		if (rtm->rtm_pid == pid && rtm->rtm_seq == seq &&
		    rtm->rtm_flags & RTF_DONE) {
			ret = rtm->rtm_flags & RTF_GATEWAY ? 0 : 1;
			break;
		}
	}
	if (seq == INT_MAX)
		seq = 0;
	seq++;
	close(s);

	return (ret);
}

static int
mdns_socket(void)
{
	int s;
	static int on = 1;

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (s < 0)
		return (-1);
	setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));

	return (s);
}	


static int
mdns_connect(int s)
{
	int ret = -1;

	if (avahi_connect(s) == 0)
		return (MDNS_RESP_AVAHI);
	if (mdnsd_connect(s) == 0)
		return (MDNS_RESP_MDNSD);

	return (ret);
}

static int
mdns_issue_name_query(int af, const char *name, struct mdns_handle *md_handle)
{
	int s;
	int type;

	bzero(md_handle, sizeof(*md_handle));
	s = mdns_socket();
	if (s < 0)
		return (-1);
	type = mdns_connect(s);
	if (type < 0) {
		close(s);
		return (-1);
	}
	md_handle->resptype = type;
	md_handle->s = s;
	md_handle->af = af;
	md_handle->reqtype = MDNS_REQ_NAME;
	if (md_handle->resptype == MDNS_RESP_AVAHI)
		avahi_issue_name_query(s, af, name);
	else
		mdnsd_issue_name_query(s, af, name);

	return (0);
}

static int
mdns_issue_addr_query(int af, const void *addr, struct mdns_handle *md_handle)
{
	int s;
	int type;
	char name[64];
	const struct in6_addr *in6;
	struct in6_addr fin6;

	s = mdns_socket();
	if (s < 0)
		return (-1);
	type = mdns_connect(s);
	if (type < 0) {
		close(s);
		return (-1);
	}
	md_handle->resptype = type;
	md_handle->s = s;
	md_handle->af = af;
	md_handle->reqtype = MDNS_REQ_ADDR;
	if (af == AF_INET6) {
		in6 = (const struct in6_addr *)addr;
		if (IN6_IS_ADDR_LINKLOCAL(in6)) {
			memcpy(&fin6, in6, sizeof(fin6));
			fin6.s6_addr[2] = 0;
			fin6.s6_addr[3] = 0;
			addr = &fin6;
		}
	}
	inet_ntop(af, addr, name, sizeof(name));
	if (md_handle->resptype == MDNS_RESP_AVAHI)
		avahi_issue_addr_query(s, name);
//	else
//		mdnsd_issue_addr_query(s, name);

	return (s);
}

static int
mdns_parse_result(struct mdns_handle *md_handle, struct mdns_result *md_res)
{
	int error;

	error = 0;
	bzero(md_res, sizeof(*md_res));
	if (md_handle->resptype == MDNS_RESP_AVAHI) {
		if (md_handle->reqtype == MDNS_REQ_NAME)
			error = avahi_parse_name_result(md_handle, md_res);
		else if (md_handle->reqtype == MDNS_REQ_ADDR)
			error = avahi_parse_addr_result(md_handle, md_res);
#if 0
	} else {
		if (md_handle->reqtype == MDNS_REQ_NAME)
			error = mdnsd_parse_name_result(md_handle, md_res);
		else if (md_handle->reqtype == MDNS_REQ_ADDR)
			error = mdnsd_parse_addr_result(md_handle, md_res);
#endif
	}
	close(md_handle->s);

	return (error);
}
