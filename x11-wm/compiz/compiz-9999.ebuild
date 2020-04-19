# Copyright 1999-2016 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit autotools eutils git-r3 gnome2-utils

DESCRIPTION="OpenGL window and compositing manager"
HOMEPAGE="https://github.com/compiz-reloaded"
EGIT_REPO_URI="https://github.com/compiz-reloaded/compiz"

LICENSE="GPL-2 LGPL-2.1 MIT"
SLOT="0"
KEYWORDS=""
IUSE="+cairo dbus fuse gnome gtk +svg"

COMMONDEPEND="
	>=dev-libs/glib-2
	dev-libs/libxml2
	dev-libs/libxslt
	media-libs/libpng:0=
	>=media-libs/mesa-6.5.1-r1
	>=x11-base/xorg-server-1.1.1-r1
	>=x11-libs/libX11-1.4
	x11-libs/libxcb
	x11-libs/libXcomposite
	x11-libs/libXdamage
	x11-libs/libXinerama
	x11-libs/libXrandr
	x11-libs/libICE
	x11-libs/libSM
	>=x11-libs/libXrender-0.8.4
	>=x11-libs/startup-notification-0.7
	virtual/glu
	cairo? (
		x11-libs/cairo[X]
	)
	dbus? (
		>=sys-apps/dbus-1.0
		dev-libs/dbus-glib
	)
	fuse? ( sys-fs/fuse )
	gnome? (
		>=gnome-base/gnome-control-center-2.16.1:2
		gnome-base/gnome-desktop:2
	)
	gnome-base/gconf:2
	gtk? (
		>=x11-libs/gtk+-2.8.0:2
		>=x11-libs/libwnck-2.18.3:1
		x11-libs/pango
	)
	svg? (
		>=gnome-base/librsvg-2.14.0:2
		>=x11-libs/cairo-1.0
	)
"

DEPEND="${COMMONDEPEND}
	virtual/pkgconfig
	x11-base/xorg-proto
"

RDEPEND="${COMMONDEPEND}
	x11-apps/mesa-progs
	x11-apps/xdpyinfo
	x11-apps/xset
	x11-apps/xvinfo
"

#DOCS=( ABOUT-NLS AUTHORS COPYING* INSTALL NEWS TODO )
DOCS=( ABOUT-NLS AUTHORS INSTALL NEWS TODO )

src_prepare() {
	echo gtk/gnome/compiz-wm.desktop.in >> po/POTFILES.skip
	echo metadata/core.xml.in >> po/POTFILES.skip

	eautoreconf
}

src_configure() {
	local myconf

	econf \
		--enable-fast-install \
		--disable-static \
		--disable-gnome-keybindings \
		--with-default-plugins \
		$(use_enable svg librsvg) \
		$(use_enable cairo annotate) \
		$(use_enable dbus) \
		$(use_enable dbus dbus-glib) \
		$(use_enable fuse) \
		$(use_enable gnome) \
		$(use_enable gnome metacity) \
		$(use_enable gtk) \
		--disable-kde4 \
		--disable-kde \
		${myconf}
}

src_install() {
	default
	#prune_libtool_files --all

	# Install compiz-manager
	#dobin "${FILESDIR}"/compiz-manager

	# Add the full-path to lspci
	#sed -i "s#lspci#/usr/sbin/lspci#" "${D}/usr/bin/compiz-manager" || die

	# Fix the hardcoded lib paths
	#sed -i "s#/lib/#/$(get_libdir)/#g" "${D}/usr/bin/compiz-manager" || die

	# Create gentoo's config file
	dodir /etc/xdg/compiz

	cat <<- EOF > "${D}/etc/xdg/compiz/compiz-manager"
	COMPIZ_BIN_PATH="/usr/bin/"
	PLUGIN_PATH="/usr/$(get_libdir)/compiz/"
	LIBGL_NVIDIA="/usr/$(get_libdir)/opengl/xorg-x11/lib/libGL.so.1.2"
	LIBGL_FGLRX="/usr/$(get_libdir)/opengl/xorg-x11/lib/libGL.so.1.2"
	KWIN="$(type -p kwin)"
	METACITY="$(type -p metacity)"
	SKIP_CHECKS="yes"
	EOF

	domenu "${FILESDIR}"/compiz.desktop
}

pkg_preinst() {
	use gnome && gnome2_gconf_savelist
}

pkg_postinst() {
	use gnome && gnome2_gconf_install

	ewarn "If you update to x11-wm/metacity-2.24 after you install ${P},"
	ewarn "gtk-window-decorator will crash until you reinstall ${PN} again."
}

pkg_prerm() {
	use gnome && gnome2_gconf_uninstall
}
