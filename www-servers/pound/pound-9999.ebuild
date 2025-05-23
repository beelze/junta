# Copyright 1999-2024 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8
inherit autotools
DESCRIPTION="A http/https reverse-proxy and load-balancer"
HOMEPAGE="https://github.com/graygnuorg/pound"
LICENSE="GPL-3"
if [ "${PV}" == "9999" ]; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/graygnuorg/pound.git"
#	EGIT_BRANCH=resolver
else
	SRC_URI="https://github.com/graygnuorg/pound/releases/download/v${PV}/${P}.tar.gz"
	KEYWORDS="amd64 ~hppa ~ppc x86"
fi

SLOT="0"

DEPEND="
	dev-libs/openssl:=
	dev-libs/libpcre2:=
    net-dns/adns
"
RDEPEND="
	${DEPEND}
	virtual/libcrypt:=
"

QA_CONFIG_IMPL_DECL_SKIP=(
	PCRE2regcomp	# Detecting broken Debian patched PCRE2
)

# DOCS=( README )

src_prepare() {
	default
	eautoreconf
	eapply_user
}
src_configure() {
	econf --with-owner=root --with-group=root
}

src_install() {
	default
	newconfd "${FILESDIR}"/${P}.confd ${PN}
	newinitd "${FILESDIR}"/${P}.initd ${PN}
	insinto /etc
	newins "${FILESDIR}"/${P}.cfg ${PN}.cfg
}
