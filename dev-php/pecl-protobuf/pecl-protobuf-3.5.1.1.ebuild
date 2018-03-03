# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=6

USE_PHP="php5-6"

inherit php-ext-pecl-r3

USE_PHP="php5-6"

KEYWORDS="~amd64 ~x86"

DESCRIPTION="Google's language-neutral, platform-neutral, extensible mechanism for serializing structured data"
LICENSE="BSD 3 Clause License"
SLOT="0"
IUSE=""

DEPEND=""
PDEPEND=""

src_prepare() {
	if use php_targets_php5-6 ; then
		php-ext-source-r3_src_prepare
	else
		eapply_user
	fi
}

src_configure() {
	if use php_targets_php5-6 ; then
		local PHP_EXT_ECONF_ARGS=( )
		php-ext-source-r3_src_configure
	fi
}

src_install() {
	if use php_targets_php5-6 ; then
		php-ext-pecl-r3_src_install
	fi
}
