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

# findfs should give partuuid and getopt? ( app-misc/getopt ) broken

IUSE="modules xfs ldd mdevd busybox device-mapper efistub findfs lvm luks blkid partuuid mdadm e2fs xz getopt mount cpio uefi-mkconfig sh secureboot switch_root zfs"


DEPEND="
        ldd? ( sys-libs/glibc )
        efistub? ( sys-kernel/hardened-sources )
        uefi-mkconfig? ( sys-boot/uefi-mkconfig )
        secureboot? ( sys-boot/shim )
        sh? ( app-shells/bash )
        cpio? ( app-alternatives/cpio )
	sys-apps/util-linux[unicode,uuidd]
        getopt? ( sys-apps/util-linux )
        findfs? ( sys-apps/util-linux )
        switch_root? ( sys-apps/util-linux )
        mount? ( sys-apps/util-linux )
	mdevd? ( sys-fs/mdevd )
	luks? ( sys-fs/cryptsetup )
	device-mapper? ( sys-fs/lvm2 )
        busybox? ( sys-apps/busybox[mdev] )
	zfs? ( sys-fs/zfs )
	xfs? ( sys-fs/xfsprogs )
        e2fs? ( sys-fs/e2fsprogs )
	xz? ( app-arch/xz-utils )
	mdadm? ( sys-fs/mdadm )
"

RDEPEND=""
IDEPEND="modules? ( sys-apps/kmod[tools] )"
RESTRICT="strip"
DESCRIPTION=
KEYWORDS="~x86 ~amd64 ~ppc"

SLOT="0.5"

src_unpack(){
	unpack ${A}
	cd "${S}"
	sed -i mkinitramfs-${SLOT}/Makefile
	sed -i mkinitramfs-${SLOT}/Makefile.lint
        sed -i mkinitramfs-${SLOT}/config.mk
}
src_compile(){
	emake || die
}

src_install(){
	emake DESTDIR="${D}" install || die "failed"
}
