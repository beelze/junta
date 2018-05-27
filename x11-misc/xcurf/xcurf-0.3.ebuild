# Copyright 1999-2018 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit autotools eutils

DESCRIPTION="an util from xneur upstream"
HOMEPAGE="https://xneur.ru/"
SRC_URI="http://dists.xneur.ru/${PN}/${P}.tar.gz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE=""

DEPEND="media-libs/imlib2"
RDEPEND="${DEPEND}"
