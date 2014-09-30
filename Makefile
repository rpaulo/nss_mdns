# $FreeBSD$

LIB=		nss_mdns
SHLIB_MAJOR=	1
SHLIB_NAME=	${LIB}.so.${SHLIB_MAJOR}
MAN=

SRCS=	nss_mdns.c

.include <bsd.lib.mk>
