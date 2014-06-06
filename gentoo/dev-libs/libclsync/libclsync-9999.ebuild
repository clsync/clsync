# Copyright 1999-2014 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=5

MY_PN=${PN#lib}
MY_PV=0.4

if [[ ${PV} == "9999" ]] ; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/xaionaro/${MY_PN}.git"
	SRC_URI=""
	KEYWORDS=""
else
	SRC_URI="https://github.com/xaionaro/${MY_PN}/archive/v${MY_PV}.tar.gz -> ${P}.tar.gz"
	KEYWORDS="~x86 ~amd64"
fi

inherit autotools eutils

DESCRIPTION="Control and monitoring library for clsync"
HOMEPAGE="http://ut.mephi.ru/oss"
LICENSE="GPL-3+"
SLOT="0"
IUSE="debug doc extra-hardened hardened static-libs"
REQUIRED_USE="
	extra-hardened? ( hardened )
"

RDEPEND=""
DEPEND="
	virtual/pkgconfig
	doc? ( app-doc/doxygen )
"

src_prepare() {
	eautoreconf
}

src_configure() {
	local harden_level=0
	use hardened && harden_level=1
	use extra-hardened && harden_level=2

	econf \
		--docdir="${EPREFIX}/usr/share/doc/${PF}" \
		--disable-clsync \
		--enable-socket-library \
		--enable-paranoid=${harden_level} \
		--disable-cluster \
		--enable-socket \
		$(use_enable debug) \
		--without-capabilities \
		--without-mhash
}

src_compile() {
	emake
	use doc && emake doc
}

src_install() {
	emake DESTDIR="${D}" install
	use doc && dohtml -r doc/html/*
	prune_libtool_files
	use static-libs || find "${ED}" -name "*.a" -delete || die "failed to remove static libs"

	# remove unwanted docs
	rm "${ED}/usr/share/doc/${PF}"/{LICENSE,TODO} || die "failed to cleanup docs"
}

pkg_postinst() {
	einfo "clsync instances you are going to use _must_ be compiled"
	einfo "with control-socket support"
}
