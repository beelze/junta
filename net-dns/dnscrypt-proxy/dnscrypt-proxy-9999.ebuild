# Copyright 1999-2016 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=6

inherit golang-build golang-vcs user

#EGO_SRC=github.com/jedisct1/dnscrypt-proxy.git
EGO_SRC=github.com/jedisct1/dnscrypt-proxy
EGO_PN=${EGO_SRC}/...

DESCRIPTION="A tool for securing communications between a client and a DNS resolver"
HOMEPAGE="http://dnscrypt.org/"
SRC_URI=""

LICENSE="ISC"
SLOT="0"
KEYWORDS=""
IUSE="+plugins systemd"

CDEPEND="
	dev-libs/libsodium
	net-libs/ldns
	systemd? ( sys-apps/systemd )"
RDEPEND="${CDEPEND}"
DEPEND="${CDEPEND}
	virtual/pkgconfig"

#DOCS="AUTHORS ChangeLog NEWS README* THANKS *txt"

pkg_setup() {
	enewgroup dnscrypt
	enewuser dnscrypt -1 -1 /var/empty dnscrypt
}

src_install() {
	default

	newinitd "${FILESDIR}"/${PN}.initd-${PV} ${PN}
	newconfd "${FILESDIR}"/${PN}.confd-${PV} ${PN}
	#systemd_dounit "${FILESDIR}"/${PN}.service
}

pkg_postinst() {
	elog "After starting the service you may want to update your"
	elog "/etc/resolv.conf and replace your current set of resolvers"
	elog "with:"
	elog
	elog "nameserver <DNSCRYPT_LOCAL_ADDRESS>"
	elog
	elog "where <DNSCRYPT_LOCAL_ADDRESS> is what you supplied in"
	elog "/etc/conf.d/dnscrypt-proxy, default is \"127.0.0.1\"."
	elog
	elog "Also see https://github.com/jedisct1/dnscrypt-proxy#usage."
	elog
	elog
	elog "But because of query process time up to 3-4 seconds on some"
	elog "nameservers from dnscrypt-proxy database you'll probably"
	elog "will want to setup local caching DNS server"
	elog "bind/unbound or something else."
}
