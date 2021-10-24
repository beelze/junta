# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

SRC_URI="http://megaseed.kz/portage/${P}.tgz"
KEYWORDS="~alpha ~amd64 ~arm ~arm64 ~hppa ~ia64 ~ppc ~ppc64 ~s390 ~sparc ~x86 ~amd64-linux ~x86-linux ~ppc-macos ~x64-macos ~sparc64-solaris"

DESCRIPTION="Gentoo specific zsh completion support (includes emerge and ebuild commands)"
HOMEPAGE="https://github.com/gentoo/gentoo-zsh-completions"

LICENSE="ZSH"
SLOT="0"

RDEPEND=">=app-shells/zsh-4.3.5"

src_install() {
	insinto /usr/share/zsh/site-functions
	doins src/_*

	dodoc AUTHORS
}
