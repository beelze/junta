# Copyright 1999-2018 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit flag-o-matic qmake-utils autotools db-use
if [[ -z ${PV%%*9999} ]]; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/${PN%-*}/${PN#*-}.git"
else
	# inherit vcs-snapshot
	# MY_PV="0fbbaa4"
	# [[ -n ${PV%%*_p*} ]] && MY_PV="v${PV}"
	# SRC_URI="
	# 	mirror://githubcl/${PN%-*}/${PN#*-}/tar.gz/${MY_PV}
	# 	-> ${P}.tar.gz
	# "
	# RESTRICT="primaryuri"
    # KEYWORDS="~amd64 ~x86"
    SRC_URI="https://github.com/meganz/sdk/archive/v${PV}.tar.gz -> ${P}.tar.gz"
fi

SLOT=0
DESCRIPTION="MEGA C++ SDK"
HOMEPAGE="https://github.com/meganz/sdk"

LICENSE="BSD-2"
# awk '/define/ {print $3}' include/mega/version.h|awk 'BEGIN{RS="";FS="\n"}{printf $1*10000+$2*100+$3}'
IUSE="examples ffmpeg freeimage fuse hardened inotify libuv mediainfo qt raw +sqlite"
REQUIRED_USE="
	examples? ( sqlite )
	fuse? ( examples )
"

DEPEND="
	dev-libs/crypto++
	sys-libs/zlib
	dev-libs/libpcre:3[cxx]
	dev-libs/openssl:0
	net-dns/c-ares
	net-misc/curl
	sqlite? ( dev-db/sqlite:3 )
	!sqlite? ( sys-libs/db:*[cxx] )
	examples? (
		sys-libs/readline:0
		fuse? ( sys-fs/fuse:0 )
	)
	freeimage? ( media-libs/freeimage )
	libuv? ( dev-libs/libuv )
	dev-libs/libsodium
	mediainfo? ( media-libs/libmediainfo )
	ffmpeg? ( virtual/ffmpeg )
	raw? ( media-libs/libraw )
"
RDEPEND="
	${DEPEND}
"

pkg_setup() {
	use sqlite || append-cppflags "-I$(db_includedir)"
}

src_unpack() {
    default
    mv ${WORKDIR}/sdk-${PV} $S || die "${WORKDIR}/sdk-${PV} not renamed!"
}

src_prepare() {
	default
	use qt && sed \
		-e '/SOURCES += src\// s:+:-:' \
		-e '/!exists.*config.h/ s:!::' \
		-e 's:CONFIG(USE_MEGAAPI) {:&\nLIBS += -lmega:' \
		-e '/^unix:!macx {/,/^}/d' \
		-i bindings/qt/sdk.pri
	eautoreconf
}

src_configure() {
	local myeconfargs=(
		--enable-chat
		$(use_enable inotify)
		$(use_enable hardened gcc-hardening)
		$(use_with libuv)
		$(use_with !sqlite db)
		$(use_with sqlite)
		$(use_enable examples)
		$(use_with freeimage)
		$(use_with fuse)
		$(use_with mediainfo libmediainfo)
		$(use_with ffmpeg)
		$(use_with raw libraw)
	)
	econf "${myeconfargs[@]}"
}

src_install() {
	default
	doheader -r include/mega

	use qt || return
	insinto /usr/share/${PN}/bindings/qt
	doins bindings/qt/*.{h,cpp,pri}
}
