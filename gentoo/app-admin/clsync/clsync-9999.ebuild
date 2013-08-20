# Copyright 1999-2013 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=5

if [[ ${PV} == "9999" ]] ; then
	inherit git-2
	EGIT_REPO_URI="https://github.com/xaionaro/clsync.git"
	SRC_URI=""
	KEYWORDS=""
else
	SRC_URI="https://github.com/xaionaro/${PN}/archive/v${PV}.tar.gz -> ${P}.tar.gz"
	KEYWORDS="~x86 ~amd64"
fi

DESCRIPTION="Live sync tool based on inotify, written in GNU C"
HOMEPAGE="http://ut.mephi.ru/oss"
LICENSE="GPL-3"
SLOT="0"
IUSE="doc examples hardened"

RDEPEND="dev-libs/glib:2"
DEPEND="${RDEPEND}
	virtual/pkgconfig
	doc? ( app-doc/doxygen )
"

src_compile() {
	# allow security flags only with hardened
	use hardened || export CSECFLAGS="" LDSECFLAGS=""
	CARCHFLAGS="" emake
	use doc && emake doc
}

src_install() {
	EXAMPLES="" COMPRESS_MAN="no" STRIP_BINARY="no" \
	emake DESTDIR="${D}" install
	dodoc CONTRIB DEVELOPING README.md
	use doc && dohtml -r doc/html/*
	use examples && dodoc -r examples
}
