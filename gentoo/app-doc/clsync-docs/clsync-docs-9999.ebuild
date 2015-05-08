# Copyright 1999-2014 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=5

MY_PN=${PN%-docs}

if [[ ${PV} == "9999" ]] ; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/xaionaro/${MY_PN}.git"
	SRC_URI=""
	KEYWORDS=""
else
	SRC_URI="https://github.com/xaionaro/${MY_PN}/archive/v${PV}.tar.gz -> ${P}.tar.gz"
	KEYWORDS="~x86 ~amd64"
fi

inherit autotools eutils

DESCRIPTION="Clsync and libclsync API documentation"
HOMEPAGE="http://ut.mephi.ru/oss/clsync https://github.com/xaionaro/clsync"
LICENSE="GPL-3+"
SLOT="0"
IUSE=""

RDEPEND=""
DEPEND="
	app-doc/doxygen
	virtual/pkgconfig
"

src_prepare() {
	eautoreconf
}

src_configure() {
	econf \
		--docdir="${EPREFIX}/usr/share/doc/${PF}" \
		--enable-socket-library \
		--disable-clsync \
		--enable-paranoid=1 \
		--with-inotify=native \
		--without-bsm \
		--without-kqueue \
		--disable-cluster \
		--enable-socket \
		--disable-debug \
		--without-capabilities \
		--without-mhash
}

src_compile() {
	emake doc
}

src_install() {
	dohtml -r doc/html/*
}
