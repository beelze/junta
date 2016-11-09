# Copyright 1999-2016 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=5

USE_RUBY="ruby20 ruby21"

RUBY_FAKEGEM_RECIPE_TEST="rspec"

inherit ruby-fakegem

DESCRIPTION="An ftp-like command-line Dropbox interface in Ruby."
HOMEPAGE="http://jangler.info/code/droxi"
SRC_URI="http://github.com/jangler/${PN}/archive/v${PV}.tar.gz"

LICENSE="as is"
SLOT="0"
KEYWORDS="~amd64 ~x86"
