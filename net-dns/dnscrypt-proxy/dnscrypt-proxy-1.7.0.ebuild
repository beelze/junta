# Copyright 1999-2016 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=5

inherit systemd user

DESCRIPTION="A tool for securing communications between a client and a DNS resolver"
HOMEPAGE="http://dnscrypt.org/"
SRC_URI="http://download.dnscrypt.org/${PN}/${P}.tar.gz"

LICENSE="ISC"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="+plugins systemd"

CDEPEND="
	dev-libs/libsodium
	net-libs/ldns
	systemd? ( sys-apps/systemd )"
RDEPEND="${CDEPEND}"
DEPEND="${CDEPEND}
	virtual/pkgconfig"

DOCS="AUTHORS ChangeLog NEWS README* THANKS *txt"

pkg_setup() {
	enewgroup dnscrypt
	enewuser dnscrypt -1 -1 /var/empty dnscrypt
}

src_configure() {
	econf \
		$(use_enable plugins) \
		$(use_with systemd)
}

src_install() {
	default

	newinitd "${FILESDIR}"/${PN}.initd-1.7.0 ${PN}
	newconfd "${FILESDIR}"/${PN}.confd-1.7.0 ${PN}
	#systemd_dounit "${FILESDIR}"/${PN}.service
}

pkg_postinst() {
	elog "After starting the service you will need to update your"
	elog "/etc/resolv.conf and replace your current set of resolvers"
	elog "with:"
	elog
	elog "nameserver <DNSCRYPT_LOCAL_ADDRESS>"
	elog
	elog "where <DNSCRYPT_LOCAL_ADDRESS> is what you supplied in"
	elog "/etc/conf.d/dnscrypt-proxy, default is \"127.0.0.1\"."
	elog
	elog "Also see https://github.com/jedisct1/dnscrypt-proxy#usage."
}