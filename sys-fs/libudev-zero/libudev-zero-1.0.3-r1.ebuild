# Port from @bluebottle to & add hotpulg helper & make static
# Copied here for easy of use
#
# https://gitlab.com/liguros/ports/-/blob/82abfa564bf74931cbda28a8499b5c081a04c5a6/sys-fs/libudev-zero/libudev-zero-1.0.3-r1.ebuild
#
# Copyright 2025 Liguros Authors
# Distributed under the terms of the GNU General Public License v2
EAPI=8

DESCRIPTION="Daemonless replacement for libudev"
HOMEPAGE="https://github.com/illiliti/libudev-zero"
SRC_URI="https://github.com/illiliti/libudev-zero/archive/refs/tags/${PV}.tar.gz -> ${P}.tar.gz"
KEYWORDS="~amd64"

LICENSE="ISC"
SLOT="0"

RDEPEND="
	!sys-apps/systemd
	!sys-apps/systemd-utils[udev]
	virtual/udev
	!sys-fs/eudev
"
DEPEND="sys-kernel/linux-headers"

PATCHES=( $FILESDIR/Makefile.patch )

src_install() {
	emake DESTDIR="${D}" PREFIX="${EPREFIX}/usr" LIBDIR="${EPREFIX}/usr/$(get_libdir)" install

	dobin ${PN}-helper
	dodoc contrib/mdev.conf
}
