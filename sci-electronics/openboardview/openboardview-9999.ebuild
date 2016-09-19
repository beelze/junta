# Copyright 1999-2016 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=6

MY_PN="OpenBoardView"

inherit git-r3 cmake-utils eutils

DESCRIPTION="Linux SDL/ImGui edition software for viewing .brd files"
HOMEPAGE="https://github.com/piernov/OpenBoardView"

EGIT_REPO_URI="https://github.com/piernov/${MY_PN}.git"

LICENSE="MIT"
SLOT="0"
KEYWORDS=""
IUSE=""

DEPEND=">=sys-devel/gcc-4.9.3
		sys-libs/zlib
		>=x11-libs/gtk+-3.18.9
		dev-db/sqlite:3
		media-libs/libsdl2[opengl]
		media-libs/fontconfig"
RDEPEND="${DEPEND}"

src_install() {
		cmake-utils_src_install
		#
		make_desktop_entry openboardview ${MY_PN}
}
