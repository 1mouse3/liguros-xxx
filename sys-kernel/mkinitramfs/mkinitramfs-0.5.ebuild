# Sourced from this lot of folks for this ebuild by mouse <1mouse3@gmail.com>
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

IUSE="uefi mdevd busybox device-mapper lvm luks blkid xz zfs"


DEPEND="
	ldd
	ys-apps/util-linux[blkid,uuid,partuuid]
	mdevd? ( sys-fs/mdevd )
	luks? ( sys-fs/cryptsetup )
	device-mapper? ( sys-fs/lvm2 )
	busybox? ( sys-apps/busybox[loadkmap,mdev] )
	zfs? ( sys-fs/zfs )
	xfs? ( sys-fs/xfsprogs )
        e2fs? ( sys-fs/e2fsprogs )
	xz? ( app-arch/xz-utils )
	#mdadm? ( sys-fs/mdadm )
"

RDEPEND="sys-apps/sed, !systemd"
IDEPEND="modules? ( sys-apps/kmod[tools] )"
RESTRICT="strip"
DESCRIPTION=
KEYWORDS="~x86 ~amd64 ~ppc"


src_unpack(){
	unpack ${A}
	cd "${S}"
	sed -i 's:DESTDIR:PREFIX:' src/mkinitramfs-0.5/Makefile
	sed -i 's:$(PREFIX):$(DESTDIR)$(PREFIX):' src/mkinitramfs-0.5/Makefile
}
src_compile(){
	emake || die
}

src_install(){
	emake DESTDIR="${D}" install || die "failed"
}
