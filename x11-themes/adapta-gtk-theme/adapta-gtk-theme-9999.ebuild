# Copyright 1999-2016 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=6

inherit gnome2 autotools

DESCRIPTION="An adaptive GTK+ theme based on Material Design Guidelines"
HOMEPAGE="https://github.com/tista500/Adapta"

if [[ ${PV} == *9999* ]];then
	inherit git-r3
	SRC_URI=""
	EGIT_REPO_URI="${HOMEPAGE}"
	KEYWORDS=""
else
	SRC_URI="${HOMEPAGE}/archive/${PV}.tar.gz -> ${P}.tar.gz"
	KEYWORDS="~*"
	RESTRICT="mirror"
	S="${WORKDIR}/Adapta-${PV}"
fi

LICENSE="GPL-2"
SLOT="0"
IUSE="gnome gtk318 gtk4 parallel cinnamon flashback xfce mate openbox chrome plank telegram"

RDEPEND="
	x11-libs/gtk+:2
	>=dev-ruby/sass-3.4.21:3.4
	>=dev-ruby/bundler-1.11
	media-gfx/inkscape
	dev-libs/libxml2:2
"
DEPEND="${RDEPEND}
	parallel? ( sys-process/parallel )
    dev-lang/sassc"

src_prepare(){
	eautoreconf
	if use gnome; then
		gnome2_src_prepare
	else
		default
	fi
	# gnome2_src_prepare
}

src_configure() {
	econf $(use_enable gnome) \
		  $(use_enable parallel) \
		  $(use_enable cinnamon) \
		  $(use_enable flashback) \
		  $(use_enable xfce) \
		  $(use_enable mate) \
		  $(use_enable openbox) \
		  $(use_enable chrome) \
		  $(use_enable plank) \
		  $(use_enable telegram) \
		  $(use_enable gtk318 gtk_legacy) \
		  $(use_enable gtk4 gtk_next)
}

src_compile(){
	emake DESTDIR="${D}" || die
}

src_install(){
	emake DESTDIR="${D}" install || die
}
