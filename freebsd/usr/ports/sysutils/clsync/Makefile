# Created by: Dmitry Yu Okunev dyokunev@ut.mephi.ru
# $FreeBSD: head/sysutils/clsync/Makefile 357592 2014-06-12 12:48:11Z feld $

PORTNAME=	clsync
DISTVERSION=	0.4~rc6
PORTREVISION=	1
DIST_SUBDIR=	${PORTNAME}-${PORTVERSION}-${GH_COMMIT}
CATEGORIES=	sysutils

MAINTAINER=	dyokunev@ut.mephi.ru
COMMENT=	Live file sync daemon based on inotify, written in GNU C

LICENSE=	GPLv3

LIB_DEPENDS=	libinotify.so:${PORTSDIR}/devel/libinotify \
		libexecinfo.so:${PORTSDIR}/devel/libexecinfo

GNU_CONFIGURE=	yes
USES=		gmake libtool pkgconfig
USE_GNOME=	glib20

USE_RC_SUBR=	clsync

SUB_FILES=	pkg-message

USE_GITHUB=	yes
GH_ACCOUNT=	xaionaro
GH_PROJECT=	clsync
GH_COMMIT=	85e5475
GH_TAGNAME=	${GH_COMMIT}

USE_AUTOTOOLS=	autoconf aclocal automake libtoolize

OPTIONS_DEFINE=	PARANOID VERYPARANOID SOCKET DEBUG LIBCLSYNC
OPTIONS_DEFAULT=PARANOID

PARANOID_DESC=	Paranoid secure routines
VERYPARANOID_DESC=Extra paranoid secure routines, less features
SOCKET_DESC=	Control socket support
LIBCLSYNC_DESC=	Build libclsync.so for control socket clients

OPTIONS_MULTI=	MONITOR
OPTIONS_MULTI_MONITOR=	BSM KQUEUE LIBINOTIFY GIO
KQUEUE_DESC=	"Kqueue" monitor support
BSM_DESC=	"BSM" monitor support
LIBINOTIFY_DESC="Inotify" monitor support (via libinotify-kqueue)
GIO_DESC=	"GIO" monitor support
OPTIONS_DEFAULT+=KQUEUE BSM

LIBS+=          -L${LOCALBASE}/lib
CPPFLAGS+=      -I${LOCALBASE}/include

.include <bsd.port.options.mk>

.if ${PORT_OPTIONS:MBSM}
CONFIGURE_ARGS+=	--with-bsm=lib
.endif

.if ${PORT_OPTIONS:MKQUEUE}
CONFIGURE_ARGS+=	--with-kqueue=native
.endif

.if ${PORT_OPTIONS:MLIBINOTIFY}
CONFIGURE_ARGS+=	--with-inotify=lib
.endif

.if ${PORT_OPTIONS:MGIO}
CONFIGURE_ARGS+=	--with-gio=check
.endif

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
	cd "${WRKSRC}" && ${AUTORECONF} -fi

do-install:
	@${INSTALL_SCRIPT} ${WRKSRC}/clsync ${STAGEDIR}/${PREFIX}/sbin/clsync
	${INSTALL_DATA} ${WRKSRC}/man/man1/clsync.1 ${STAGEDIR}/${PREFIX}/man/man1/clsync.1
	${MKDIR} ${STAGEDIR}/${ETCDIR}
	${INSTALL_DATA} ${WRKSRC}/freebsd/usr/local/etc/clsync/${PORTNAME}.conf ${STAGEDIR}/${ETCDIR}/${PORTNAME}.conf.sample

.include <bsd.port.post.mk>
