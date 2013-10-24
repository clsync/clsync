# Copyright 1999-2013 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=5

if [[ ${PV} == "9999" ]] ; then
	_GIT=git-2
	EGIT_REPO_URI="https://github.com/xaionaro/${PN}.git"
	SRC_URI=""
	KEYWORDS=""
else
	SRC_URI="https://github.com/xaionaro/${PN}/archive/v${PV}.tar.gz -> ${P}.tar.gz"
	KEYWORDS="~x86 ~amd64"
fi

inherit autotools $_GIT

DESCRIPTION="Live sync tool based on inotify, written in GNU C"
HOMEPAGE="http://ut.mephi.ru/oss"
LICENSE="GPL-3+"
SLOT="0"
IUSE="-caps -cluster debug doc +examples extra-hardened hardened mhash"
REQUIRED_USE="
	extra-hardened? ( hardened )
	mhash? ( cluster )"

RDEPEND="
	caps? ( sys-libs/libcap )
	mhash? ( app-crypt/mhash )
	dev-libs/glib:2
"
DEPEND="${RDEPEND}
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
		--enable-paranoid=${harden_level} \
		$(use_enable cluster) \
		$(use_enable debug) \
		$(use_with caps capabilities) \
		$(use_with mhash)
}

src_compile() {
	emake
	use doc && emake doc
}

src_install() {
	emake DESTDIR="${D}" install
	use doc && dohtml -r doc/html/*

	# remove unwanted docs
	rm "${ED}/usr/share/doc/${PF}"/{LICENSE,TODO} || die
	use examples || rm -r "${ED}/usr/share/doc/${PF}/examples" || die

	newinitd "${FILESDIR}/${PN}.initd" "${PN}"
	newconfd "${FILESDIR}/${PN}.confd" "${PN}"

	# filter rules and sync scripts are supposed to be here
	keepdir "${EPREFIX}/etc/${PN}"
	insinto "/etc/${PN}"
	doins "${FILESDIR}/${PN}.conf"
}

pkg_postinst() {
	einfo "${PN} is just a convenient way to run synchronization tools on live data,"
	einfo "it doesn't copy data itself, so you need to install software to do actual"
	einfo "data transfer. Usually net-misc/rsync is a good choise, but ${PN} is"
	einfo "is flexible enough to use any user tool, see manual page for details."
	einfo
	einfo "${PN} init script can now be multiplexed, to use symlink init script to"
	einfo "othername and use conf.d/othername to configure it."
}
