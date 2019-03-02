# Copyright 1999-2018 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit git-r3 autotools

DESCRIPTION="NFC-based PAM authentification module"
HOMEPAGE="https://github.com/nfc-tools/pam_nfc http://nfc-tools.org/index.php?title=Pam_nfc"
EGIT_REPO_URI="https://github.com/nfc-tools/pam_nfc.git"
SRC_URI=

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64"

DEPEND=">=dev-libs/libnfc-1.7.0"

src_prepare() {
    # 1.15 because of bug#33022: Generated Makefile builds PROGRAMS before LTLIBRARIES
    WANT_AUTOMAKE=1.15 eautoreconf
    default
}

src_configure() {
    econf --prefix=/usr --sysconfdir=/etc --with-pam-dir=/lib/security
}

src_compile() {
    MAKEOPTS="-j1" emake
}

src_install() {
    emake DESTDIR="${D}" install
}
