# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=6

EGO_PN="github.com/pebbe/zmq4"

inherit golang-build golang-vcs

KEYWORDS=""

DESCRIPTION="A Go interface to ZeroMQ version 4"
HOMEPAGE="https://github.com/pebbe/zmq4"
LICENSE="BSD"
SLOT="0"
IUSE=""

DEPEND="net-libs/zeromq"

RESTRICT="test"
