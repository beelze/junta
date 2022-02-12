# Copyright 1999-2020 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=8
PYTHON_COMPAT=( python3_{8..9} )
inherit autotools python-single-r1

DESCRIPTION="Python bindings for libraries/plugins for compizconfig-settings"
HOMEPAGE="https://gitlab.com/compiz"
SRC_URI="https://gitlab.com/compiz/${PN}/uploads/11bb53f9054e95f715e631a261968e2c/${P}.tar.xz"

LICENSE="GPL-2+"
SLOT="0"
KEYWORDS="~amd64 ~x86"

REQUIRED_USE="${PYTHON_REQUIRED_USE}"
DEPEND="${PYTHON_DEPS}
	$(python_gen_cond_dep '
		dev-python/cython[${PYTHON_USEDEP}]
	')
	>=dev-libs/glib-2.6
	>=x11-libs/libcompizconfig-0.6.99
	<x11-libs/libcompizconfig-0.9
"

RDEPEND="${DEPEND}"
BDEPEND="
	virtual/pkgconfig
"


src_prepare(){
	default
	eautoreconf
}

src_install() {
	default
	find "${D}" -name '*.la' -delete || die
}
