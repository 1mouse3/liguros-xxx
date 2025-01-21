# Source from this lot of folks for this ebuild by mouse <1mouse3@gmail.com>
#
# Copyright (C) 2020-2021 illiliti                 <illiliti@protonmail.com>
# Copyright (C) 2020      Timothy Robert Bednarzyk <trbednarzyk@protonmail.com>
#
# Copyright (C) 2021-2024 Zeppe-Lin Team           <https://zeppe-lin.github.io>
# Copyright (C) 2021-2024 Alexandr Savca           <alexandr.savca89@gmail.com>
# Distributed under the terms of the GNU General Public License v3
EAPI=8

HOMEPAGE="https://github.com/zeppe-lin/mkinitramfs"
SRC_URI="https://github.com/zeppe-lin/mkinitramfs/archive/refs/tags/v0.5.tar.gz"
IUSE=""


DEPEND="sys-apps/sed"
DEPEND="
	ldd
	strip
	blkid
	mdevd
	dm-crypt? ( sys-fs/cryptsetup )
	device-mapper? ( sys-fs/lvm2 )
	sys-apps/busybox[loadkmap,mdev]
	kmod
	zfs? ( sys-fs/zfs )
	xfs? ( sys-fs/xfsprogs )
	xz? ( app-arch/xz-utils )
	mdadm? ( sys-fs/mdadm )
"

RDEPEND="sys-apps/sed"
DESCRIPTION=
KEYWORDS="~x86 ~amd64 ~ppc"


src_unpack(){
	unpack ${A}
	cd "${S}"
	sed -i 's:DESTDIR:PREFIX:' src/SFML/mkinitramfs-0.5/Makefile
	sed -i 's:$(PREFIX):$(DESTDIR)$(PREFIX):' src/mkinitramfs-0.5/Makefile
}
src_compile(){
	emake || die
}

src_install(){
	emake DESTDIR="${D}" install || die "failed"
}
