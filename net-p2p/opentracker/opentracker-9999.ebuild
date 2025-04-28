# Copyright 1999-2024 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

EGIT_REPO_URI="https://erdgeist.org/gitweb/opentracker"

declare -A FLAGS
FLAGS=(
	[ipv4-only]="DWANT_V4_ONLY"
	[gzip]='include +Makefile\.gzip'
	[gzip-always]="DWANT_COMPRESSION_GZIP_ALWAYS"
	[blacklist]="DWANT_ACCESSLIST_BLACK"
	[whitelist]="DWANT_ACCESSLIST_WHITE"
	[list-dynamic]="DWANT_DYNAMIC_ACCESSLIST"
	[live-sync]="DWANT_SYNC_LIVE"
	[restrict-stats]="DWANT_RESTRICT_STATS"
	[fullscrape]="DWANT_FULLSCRAPE"
	[fullscrapes-modest]="DWANT_MODEST_FULLSCRAPES"
	[query-ip]="DWANT_IP_FROM_QUERY_STRING"
	[woodpeckers]="DWANT_SPOT_WOODPECKER"
	[syslog]="DWANT_SYSLOGS"
)

inherit git-r3

DESCRIPTION="An open and free bittorrent tracker"
HOMEPAGE="http://erdgeist.org/arts/software/opentracker/"
SRC_URI=""

LICENSE="BEER-WARE"
SLOT="0"
KEYWORDS=""
IUSE="+ipv4-only +gzip gzip-always blacklist whitelist live-sync restrict-stats +fullscrape fullscrapes-modest query-ip woodpeckers list-dynamic syslog"
REQUIRED_USE="blacklist? ( !whitelist )
	gzip-always? ( gzip )
	gzip? ( fullscrape )
    fullscrapes-modest? ( fullscrape )
    list-dynamic? ( || ( blacklist whitelist ) )"

RDEPEND="acct-user/opentracker
	>=dev-libs/libowfat-0.34
	gzip? ( sys-libs/zlib )"

src_prepare() {
	default

	# Fix use of FEATURES, so it's not mixed up with portage's FEATURES, and comment all of them
	# Define PREFIX, BINDIR and path to libowfat; remove lpthread, lz and O3 flag, owfat target, stripping; create dirs on install
	sed -i \
		-e "s|FEATURES|FEATURES_INTERNAL|g" \
		-e "s|^FEATURES_INTERNAL|#FEATURES_INTERNAL|g" \
		-e "s|PREFIX?=..|PREFIX?=/usr|g" \
		-e "s|LIBOWFAT_HEADERS=\$(PREFIX)/libowfat|LIBOWFAT_HEADERS=\$(PREFIX)/include/libowfat|g" \
		-e "s|-O3||g" \
		-e "s|BINDIR?=\$(PREFIX)/bin|BINDIR?=\$(DESTDIR)\$(PREFIX)/bin/|g" \
		-e "s|install -m 755 ${PN} \$(DESTDIR)\$(BINDIR)|install -D -m 755 ${PN} \$(BINDIR)/${PN}|g" \
		Makefile || die "sed for src_prepare failed"

	# Define which features to use
	for flag in "${!FLAGS[@]}" ; do
		sed -i "$(usex "$flag" /"${FLAGS[$flag]}"/s/^#*// '')" Makefile Makefile.gzip || die "sed for $flag failed"
	done

	# Correct config paths
	sed -i \
		-e "/access\.whitelist/s|/path/to/whitelist|/access.whitelist|g" \
		-e "/access\.blacklist/s|./blacklist|/access.blacklist|g" \
		-e "/access\.fifo_delete/s|/var/run/opentracker/deleter\.fifo|/deleter.fifo|g" \
		-e "/access\.fifo_add/s|/var/run/opentracker/adder\.fifo|/adder.fifo|g" \
		-e "/tracker\.rootdir/c\tracker.rootdir /var/lib/${PN}" \
		-e "/tracker\.user/c\tracker.user ${PN}" \
		opentracker.conf.sample || die "sed for config failed"
}

src_install() {
	default

	doman man1/opentracker.1
	doman man4/opentracker.conf.4

	newinitd "${FILESDIR}/${PF}".initd opentracker
	newconfd "${FILESDIR}/${PF}".confd opentracker
	# systemd_dounit "${FILESDIR}"/opentracker.service

	insopts -m 644 -o opentracker -g opentracker
	diropts -m 755 -o opentracker -g opentracker
	insinto /etc/opentracker
	newins opentracker.conf.sample opentracker.conf
	keepdir /var/lib/opentracker
}
