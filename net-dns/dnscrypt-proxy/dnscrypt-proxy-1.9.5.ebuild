# Copyright 1999-2016 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=5

inherit systemd user

DESCRIPTION="A tool for securing communications between a client and a DNS resolver"
HOMEPAGE="http://dnscrypt.org/"
SRC_URI="http://download.dnscrypt.org/${PN}/${P}.tar.bz2"

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
		--sysconfdir=/etc/"${PN}" \
		$(use_enable plugins) \
		$(use_with systemd)
}

src_install() {
	default

	exeinto /usr/libexec
	doexe "${FILESDIR}"/dnscrypt-proxies.py
	insinto "/etc/${PN}"
	doins "${FILESDIR}"/dnscrypt-proxies.conf
	newinitd "${FILESDIR}"/${PN}.initd ${PN}
	keepdir "/var/log/${PN}"
	fowners dnscrypt:dnscrypt "/var/log/${PN}"
	#newinitd "${FILESDIR}"/${PN}.initd-1.7.0 ${PN}
	#newconfd "${FILESDIR}"/${PN}.confd-1.7.0 ${PN}
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
	elog "/etc/dnscrypt-proxies.conf, default is \"127.0.0.100\"."
	elog
	elog "For use with local DNS chache server add addresses above"
	elog "in it's config and dependency in service's config."
	elog "For example for unbound place line in /etc/conf.d/unbound:"
	elog
	elog "rc_need=\"cryptodns\""
}
