# Copyright 1999-2019 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=6

# 1.15 because of bug#33022: Generated Makefile builds PROGRAMS before LTLIBRARIES
WANT_AUTOMAKE=1.15

inherit git-r3 autotools pam

DESCRIPTION="NFC-based PAM authentification module"
HOMEPAGE="https://github.com/nfc-tools/pam_nfc http://nfc-tools.org/index.php?title=Pam_nfc"
EGIT_REPO_URI="https://github.com/nfc-tools/pam_nfc.git"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64"
IUSE="static-libs"

DEPEND=">=dev-libs/libnfc-1.7.0"

src_prepare() {
	default
	eautoreconf
}

src_configure() {
	econf \
		"--with-pam-dir=$(getpam_mod_dir)"
}

src_compile() {
	MAKEOPTS="-j1" emake
}

src_install() {
	default
	use static-libs || find "${ED}" -name '*.la' -delete
}
