# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=6

inherit git-r3 cmake-utils

DESCRIPTION="A tool to verify sources of dnscrypt-proxy"
HOMEPAGE="https://jedisct1.github.io/minisign/"
EGIT_REPO_URI="https://github.com/jedisct1/minisign.git"

LICENSE="ISC"
SLOT="0"
KEYWORDS=""
IUSE=""

DEPEND="dev-libs/libsodium"
RDEPEND="${DEPEND}"
