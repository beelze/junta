# Copyright 2023-2024 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit cmake

DESCRIPTION="toml11 is a C++11 (or later) header-only toml parser/encoder depending only on C++ standard library."
HOMEPAGE="https://github.com/ToruNiina/toml11"
LICENSE="MIT"
SLOT="0"
KEYWORDS="~amd64 ~x86 ~x86-linux"

if [[ "${PV}" == "9999" ]]; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/ToruNiina/toml11.git"
else
	SRC_URI="https://github.com/ToruNiina/toml11/archive/refs/tags/v${PV}.tar.gz -> ${P}.tar.gz"
fi

src_prepare() {
    eapply_user
    append-cxxflags -std=c++11
    cmake_src_prepare
}
