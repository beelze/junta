# Copyright 1999-2020 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=8
PYTHON_COMPAT=( python3_{8..9} )
inherit git-r3 distutils-r1

DESCRIPTION="An easy to use tool to change the mapping of your input device buttons"
HOMEPAGE="https://github.com/sezanzeb/input-remapper"
LICENSE="GPL-3"
EGIT_REPO_URI="https://github.com/sezanzeb/input-remapper"

LICENSE="GPL-2+"
SLOT="0"
KEYWORDS=""

DEPEND="sys-devel/gettext
	dev-python/setuptools
	dev-python/python-evdev
	dev-python/pydbus
	dev-python/pygobject
	dev-python/pydantic"

distutils_enable_tests setup.py
