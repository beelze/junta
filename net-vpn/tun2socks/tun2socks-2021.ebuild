# Copyright 1999-2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8
inherit cmake toolchain-funcs

DESCRIPTION="tun2socks proxifier"
HOMEPAGE="https://github.com/ambrop72/badvpn https://code.google.com/p/badvpn/"
SRC_URI="https://megaseed.kz/portage/${P}.tgz"

LICENSE="BSD"
KEYWORDS="~amd64"
SLOT="0"
DEPEND="virtual/pkgconfig"

S=${WORKDIR}/${PN}-${PV/_rc/rc}
LDFLAGS="${LDFLAGS} -lpthread"

src_configure() {
	local mycmakeargs=(
	    -DBUILD_NOTHING_BY_DEFAULT=1
	    -DBUILD_TUN2SOCKS=1
	    -DBUILD_UDPGW=1
		-DBUILD_SHARED_LIBS=OFF
	)
	cmake_src_configure
}
