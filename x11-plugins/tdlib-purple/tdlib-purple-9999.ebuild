# Copyright 1999-2020
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cmake git-r3

DESCRIPTION="New libpurple plugin for Telegram"
HOMEPAGE="https://github.com/ars3niy/tdlib-purple"
EGIT_REPO_URI="https://github.com/ars3niy/${PN}.git"

LICENSE="*"
SLOT=0
KEYWORDS="~amd64 ~x86"

RDEPEND="
	media-libs/libpng
	media-libs/libwebp
	net-im/pidgin
	net-libs/tdlib
"
DEPEND="${RDEPEND}"

src_prepare() {
    cmake_src_prepare
}

src_configure() {
    local mycmakeargs=( -DNoVoip=True )
    cmake_src_configure
}

src_compile() {
    # emake -DNoVoip=True
    cmake_src_compile
}
