# Copyright 1999-2018 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit autotools xdg-utils git-r3 eutils

DESCRIPTION="A lightweight GTK image viewer forked from GQview"
HOMEPAGE="http://www.geeqie.org"
EGIT_REPO_URI="https://github.com/BestImageViewer/geeqie"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS=""
IUSE="debug doc exif ffmpegthumbnailer gpu-accel gtk3 jpeg lcms lirc lua map tiff xmp"

RDEPEND="gtk3? ( x11-libs/gtk+:3 )
	!gtk3? ( x11-libs/gtk+:2 )
	virtual/libintl
	doc? ( app-text/gnome-doc-utils )
	ffmpegthumbnailer? ( media-video/ffmpegthumbnailer )
	gpu-accel? ( media-libs/clutter-gtk )
	jpeg? ( virtual/jpeg:0 )
	lcms? ( media-libs/lcms:2 )
	lirc? ( app-misc/lirc )
	lua? ( >=dev-lang/lua-5.1:= )
	map? ( media-libs/libchamplain:0.12 )
	xmp? ( >=media-gfx/exiv2-0.17:=[xmp] )
	!xmp? ( exif? ( >=media-gfx/exiv2-0.17:= ) )
	tiff? ( media-libs/tiff:0 )"
DEPEND="${RDEPEND}
	virtual/pkgconfig
	dev-util/intltool
	sys-devel/gettext"

REQUIRED_USE="gpu-accel? ( gtk3 )
	map? ( gpu-accel )"

src_prepare() {
	default

	# Missing from release tarball, and requires git tree to generate
	sed -e "/readme_DATA/s/ChangeLog\(.html\)\?//g" -i Makefile.am || die

	# Remove -Werror (gcc changes may add new warnings)
	sed -e '/CFLAGS/s/-Werror //g' -i configure.ac || die

	eautoreconf
}

src_configure() {
	local myconf="--disable-dependency-tracking
		--with-readmedir="${EPREFIX}"/usr/share/doc/${PF}
		$(use_enable debug debug-log)
		$(use_enable ffmpegthumbnailer)
		$(use_enable gpu-accel)
		$(use_enable gtk3)
		$(use_enable jpeg)
		$(use_enable lcms)
		$(use_enable lua)
		$(use_enable lirc)
		$(use_enable map)
		$(use_enable tiff)"

	if use exif || use xmp; then
		myconf="${myconf} --enable-exiv2"
	else
		myconf="${myconf} --disable-exiv2"
	fi

	econf ${myconf}
}

src_install() {
	default

	rm -f "${D}/usr/share/doc/${PF}/COPYING"
	# Application needs access to the uncompressed file
	docompress -x /usr/share/doc/${PF}/README.md
}

pkg_postinst() {
	xdg_desktop_database_update

	elog "Some plugins may require additional packages"
	optfeature "JPEG image rotation." media-gfx/fbida
	optfeature "TIFF/PNG image rotation." media-gfx/imagemagick
	optfeature "RAW image display." media-gfx/ufraw
}

pkg_postrm() {
	xdg_desktop_database_update
}
