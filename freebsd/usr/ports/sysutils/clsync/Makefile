# Created by: Dmitry Yu Okunev dyokunev@ut.mephi.ru
# $FreeBSD: head/sysutils/clsync/Makefile 2014-05-23 16:38:52Z $

PORTNAME=	clsync
PORTVERSION=	0.4~rc1
CATEGORIES=	sysutils
MASTER_SITES=	http://mirror.mephi.ru/projects/clsync/archive/

MAINTAINER=	dyokunev@ut.mephi.ru
COMMENT=	file live sync daemon based on inotify, written in GNU C

LICENSE=	GPLv3
GNU_CONFIGURE=	yes
USES=		gmake

LIB_DEPENDS=	libinotify.so:${PORTSDIR}/devel/libinotify

SUB_FILES=	pkg-message

PLIST_FILES=	sbin/clsync \
		etc/rc.d/clsync \
		etc/clsync/clsync.conf \
		man/man1/clsync.1.gz


OPTIONS_DEFINE=	PARANOID VERYPARANOID SOCKET DEBUG LIBCLSYNC

PARANOID_DESC=	Enable paranoid secure routines
VERYPARANOID_DESC=Enable extra paranoid secure routines and disable some extra features
SOCKET_DESC=	Enable control socket support
LIBCLSYNC_DESC=	Build libclsync.so for control socket clients

OPTIONS_DEFAULT=PARANOID

.include <bsd.port.options.mk>

.if ${PORT_OPTIONS:MVERYPARANOID}
CONFIGURE_ARGS+=	--enable-paranoid=2
.else
.if ${PORT_OPTIONS:MPARANOID}
CONFIGURE_ARGS+=	--enable-paranoid=1
.else
CONFIGURE_ARGS+=	--enable-paranoid=0
.endif
.endif

.if ${PORT_OPTIONS:MSOCKET}
CONFIGURE_ARGS+=	--enable-socket
.endif

.if ${PORT_OPTIONS:MDEBUG}
CONFIGURE_ARGS+=	--enable-debug
.endif

.if ${PORT_OPTIONS:MLIBCLSYNC}
CONFIGURE_ARGS+=	--enable-libclsync
.endif

.include <bsd.port.pre.mk>

pre-configure:
	cd "${WRKSRC}" && autoreconf -fi

do-install:
	@${INSTALL_SCRIPT} ${WRKSRC}/clsync ${STAGEDIR}${PREFIX}/sbin/clsync
	${INSTALL_MAN} ${WRKSRC}/man/man1/clsync.1 ${STAGEDIR}${PREFIX}/man/man1/clsync.1
	${INSTALL_SCRIPT} ${WRKSRC}/freebsd/usr/local/etc/rc.d/clsync ${STAGEDIR}${PREFIX}/etc/rc.d/clsync
	${INSTALL_DATA} ${WRKSRC}/freebsd/usr/local/etc/clsync/${PORTNAME}.conf ${STAGEDIR}${PREFIX}/etc/clsync/${PORTNAME}.conf

.include <bsd.port.post.mk>

