# Copyright 1999-2024 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

DESCRIPTION="Advanced, easy to use, asynchronous-capable DNS client library and utilities."
HOMEPAGE="http://www.chiark.greenend.org.uk/~ian/adns/"

SRC_URI="https://www.chiark.greenend.org.uk/~ian/adns/ftp/${P}.tar.gz"
LICENSE="GPL-2+"
SLOT="0"
KEYWORDS="~amd64"


src_install() {
	local _d
	for _d in src dynamic client regress; do
		sed -i -e 's:\$(DESTDIR)\$:\$:' $_d/Makefile || die
	done
	emake DESTDIR="${D}" install
	dodoc NEWS README
}
