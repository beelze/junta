# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit toolchain-funcs

DESCRIPTION="QEmacs is a very small but powerful UNIX editor"
HOMEPAGE="https://savannah.nongnu.org/projects/qemacs/"
# snapshot of http://cvs.savannah.gnu.org/viewvc/?root=qemacs
SRC_URI="https://dev.gentoo.org/~ulm/distfiles/${P}.tar.xz"

LICENSE="LGPL-2.1+ GPL-2+"
SLOT="0"
KEYWORDS="amd64 arm ~ppc ~riscv x86"
IUSE="gui png xv -minimal"
REQUIRED_USE="gui? ( !minimal ) png? ( !minimal ) xv? ( !minimal )"
RESTRICT="test"

RDEPEND="
	!minimal? (
		 gui? ( x11-libs/libX11
		      	x11-libs/libXext
			xv? ( x11-libs/libXv ) )
		 png? ( >=media-libs/libpng-1.2:0= ) )"

DEPEND="${RDEPEND}
	!minimal? ( >=app-text/texi2html-5
	            gui? ( x11-base/xorg-proto ) )"

S="${WORKDIR}/${PN}"

src_prepare() {
	eapply "${FILESDIR}/${P}-Makefile.patch"
	eapply "${FILESDIR}/${P}-nostrip.patch"
	eapply_user

	# Change the manpage to reference a /real/ file instead of just an
	# approximation.  Purely cosmetic!
	eapply "${FILESDIR}/${P}-manpage.patch"
	sed -i -e "s:@PF@:${PF}:" qe.1 || die
}

src_configure() {
	# Home-grown configure script, doesn't support most standard options
	./configure \
		--prefix=/usr \
		--mandir=/usr/share/man \
		--cc="$(tc-getCC)" \
		$(use_enable gui x11) \
		$(use_enable png) \
		$(use_enable xv) \
		$(use_enable !minimal xshm) \
		$(use_enable !minimal xrender) \
		$(use_enable !minimal html) \
		$(use_enable !minimal plugins) \
		$(use_enable !minimal ffmpeg) || die

  # --disable-xshm           disable XShm extension support
  # --disable-xrender        disable Xrender extension support
  # --enable-tiny            build a very small version
  # --disable-html           disable graphical html support
  # --disable-plugins        disable plugins support
  # --disable-ffmpeg         disable ffmpeg support
}

src_install() {
    emake install DESTDIR="${D}"
    dodoc Changelog README TODO.org config.eg
    docinto html
    dodoc qe-doc.html

    if use !minimal; then
	# Install headers so users can build their own plugins
	insinto /usr/include/qe
	doins *.h
	insinto /usr/include/qe/libqhtml
	doins libqhtml/*.h
    fi
}
