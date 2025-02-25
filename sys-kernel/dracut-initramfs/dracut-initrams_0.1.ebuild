###
### This is cut from debian-sources by 1mouse3 
###
# Copyright 2020-2023 Liguros Authors
# Distributed under the terms of the GNU General Public License v2
EAPI=8

inherit check-reqs mount-boot toolchain-funcs

DESCRIPTION="Script to auto run dracut"
LICENSE="GPL-2"
KEYWORDS="x86 amd64 arm arm64"

SLOT=$(ver_cut 1-2)

RESTRICT="binchecks strip mirror"

IUSE="binary btrfs clang compact custom-cflags debug dtrace dmraid ec2 efi efistub +firmware iscsi initramfs initramfs13  libressl luks lvm  mdadm mcelog +microcode multipath NetworkManager nfs nbd nvidia plymouth +savedconfig selinux openssl +sign-modules secureboot systemd qemu wireguard xen zfs tree"

REQUIRED_USE="hardened symlink"

BDEPEND="
	sys-devel/bc
	debug? ( dev-util/dwarves )
	virtual/libelf
	qemu? (  alpha? ( app-emulation/qemu[qemu_softmmu_targets_alpha] )
		amd64? ( app-emulation/qemu[qemu_softmmu_targets_x86_64] )
		arm? ( app-emulation/qemu[qemu_softmmu_targets_arm] )
		arm64? ( app-emulation/qemu[qemu_softmmu_targets_aarch64] )
		hppa? ( app-emulation/qemu[qemu_softmmu_targets_hppa] )
		loong? ( app-emulation/qemu[qemu_softmmu_targets_loongarch64] )
		mips? ( || (
			app-emulation/qemu[qemu_softmmu_targets_mips]
			app-emulation/qemu[qemu_softmmu_targets_mips64]
			app-emulation/qemu[qemu_softmmu_targets_mips64el]
		) )
		ppc? ( app-emulation/qemu[qemu_softmmu_targets_ppc] )
		ppc64? ( app-emulation/qemu[qemu_softmmu_targets_ppc64] )
		riscv? ( || (
			app-emulation/qemu[qemu_softmmu_targets_riscv32]
			app-emulation/qemu[qemu_softmmu_targets_riscv64]
		) )
		sparc? ( || (
			app-emulation/qemu[qemu_softmmu_targets_sparc]
			app-emulation/qemu[qemu_softmmu_targets_sparc64]
		) )
		x86? ( app-emulation/qemu[qemu_softmmu_targets_i386] )
	)
"

DEPEND="
	net-misc/dhcp[client]
	btrfs? ( sys-fs/btrfs-progs )
	dtrace? (
		app-emulation/qemu[systemtap]
		dev-util/dtrace-utils
		dev-libs/libdtrace-ctf
	)
	efi? ( sys-boot/efibootmgr )
	firmware? (
		sys-kernel/linux-firmware
	)
        initramfs? ( sys-kernel/installkernel[dracut]
                    sys-kernel/dracut
		    sys-apps/kmod
		    NetworkManager? ( net-misc/networkmanager )
                    dev-util/pahole
                    sys-fs/squashfs-tools
                    lvm? ( sys-kernel/genkernel
                           sys-fs/lvm2[lvm,-thin] )
	)
        initramfs13? ( sys-kernel/dracut
                    sys-apps/kmod
                    net-misc/networkmanager[NetworkManager]
        )
	luks? ( sys-fs/cryptsetup )
	mcelog? ( app-admin/mcelog )
	multipath? (
		app-emulation/qemu[multipath]
		sys-fs/multipath-tools
	)
	plymouth? (
		 x11-libs/libdrm
		 sys-boot/plymouth[udev]
	)
	iscsi? ( app-emulation/qemu[iscsi,nfs] )
	dmraid? ( sys-fs/dmraid )
        mdadm? ( sys-fs/mdadm )
	nfs? ( net-fs/nfs-utils
		app-emulation/qemu[nfs]
	)
	sign-modules? (
		|| ( dev-libs/openssl
		     dev-libs/libressl
        )
		sys-apps/kmod
	)
	openssl? ( dev-libs/openssl )
	systemd? ( sys-apps/systemd )
	!systemd? ( virtual/udev )
	wireguard? ( virtual/wireguard )
	xen? ( app-emulation/qemu[xen] )
	zfs? ( sys-fs/zfs )
	secureboot? ( sys-firmware/edk2-bin[secureboot] )
"

RDEPEND="
	app-alternatives/cpio
	>=app-shells/bash-4.0:0
	sys-apps/coreutils[xattr(-)]
	>=sys-apps/kmod-23[tools]
	|| (
		>=sys-apps/sysvinit-2.87-r3
		sys-apps/openrc[sysv-utils(-),selinux?]
		sys-apps/openrc-navi[sysv-utils(-),selinux?]
		sys-apps/systemd[sysv-utils]
		sys-apps/s6-linux-init[sysv-utils(-)]
	)
	>=sys-apps/util-linux-2.21
	virtual/pkgconfig[native-symlinks(+)]
	virtual/udev (
		app-emulation/qemu[udev]
	)
	selinux? (
		sec-policy/selinux-dracut
		sys-libs/libselinux
		sys-libs/libsepol
	)
"

## dracut wants this for a compact libc -- elibc_musl? ( sys-libs/fts-standalone )
DEB_PV_BASE=${PV/_*/} #5.8.7
DEB_EXTRAVERSION=${PV/*_p/-} #-1
EXTRAVERSION=${PV/*_/_} #_p1

TEMP_EXTRA_VERSION="debian"

# at a minimum we will append EXTRAVERSION (debian patch set revision) and TEMP_EXTRA_VERSION (debian name) to MODULE_EXT
# if we have a local revision, we append that between EXTRAVERSION and TEMP_EXTRA_VERSION, e.g. _p1-debian-r5
# if we do not have a local revision, then we have only EXTRAVERSION and TEMP_EXTRA_VERSION, e.g. _p1-debian
if [ "${PR}" != "r0" ]; then
    MODULE_EXT=${EXTRAVERSION}-${TEMP_EXTRA_VERSION}-${PR}
else
    MODULE_EXT=${EXTRAVERSION}-${TEMP_EXTRA_VERSION}
fi

DEB_PV=${DEB_PV_BASE}${DEB_EXTRAVERSION}"
KERNEL=linux_${DEB_PV_BASE}.orig.tar.xz
DEB_PATCH=linux_${DEB_PV}.debian.tar.xz

DISTDIR=/var/cache/portage/distfiles/
S=${WORKDIR}/linux-${DEB_PV_BASE}

#########################################
# modules installkernel can run live here
# @=/usr/lib/kernel/install.d/
#############################

KERNELTAGS=${DEB_PV_BASE}-debian1
KERNELTAG=${DEB_PV_BASE}${MODULE_EXT}
D_FILESDIR="${D}/var/db/repos/liguros-xxx/sys-kernel/debian-sources/files"
PORTAGE_BUILDDIR="/var/tmp/portage/sys-kernel/debian-sources-6.1.124_p1-r1"
USR_SRC_BUILD="${D}/lib/modules/${KERNELTAGS}/build"
USR_SRC_BUILD_EXT="${D}/lib/modules/${KERNELTAGS}/.extra/build"
CERTSDIR_NEW="${D}/etc/kernel/certs/${KERNELTAGS}"
NVIDIA_MODULES=${S}drivers/video
LIB_MODULES=${D}/lib/modules/${KERNELTAGS}

# cairfull using these, becuase can cause a sandbox violation
SAVEDCONFIG="/etc/portage/savedconfig/${CATEGORY}/${PN}"
CERTSDIR="/etc/kernel/certs/${MODULE_EXT}"
CLEAN_LIB="/lib/modules/${KERNELTAGS}"
CLEAN_USR="/usr/src/linux-${KERNELTAG}"
CLEAN_NVIDIA="/usr/src/linux/drivers/video"




src_unpack() {
	# Patches to graphene source
	rsync -a ${FILESDIR}/${SLOT}/ ${SLOT} || die "failed to copy patch"
}

src_prepare() {
   if use binary; then
        ENV_SETUP_MAKECONF
	debug-print-function ${FUNCNAME} ${@}


	if use nvidia; then
		rsync -ar ${CLEAN_NVIDIA}/ ${NVIDIA_MODULES}
	fi

        cd ${S}
   fi

	#${@}=35-amd-microcode-systemd.install
	#${@}=35-intel-microcode-systemd.install
}

src_test() {
	addwrite /dev/kvm
	# Translate ARCH so run-qemu can find the correct qemu-system-ARCH
	local qemu_arch
	if use amd64; then
		qemu_arch=x86_64
	elif use arm64; then
		qemu_arch=aarch64
	elif use loong; then
		qemu_arch=loongarch64
	elif use x86; then
		qemu_arch=i386
	else
		qemu_arch=$(tc-arch)
	fi
	ARCH=${qemu_arch} emake -C test check
}

src_configure() {
        unset KBUILD_OUTPUT
        ENV_SETUP_MAKECONF
   if use initramfs; then
        echo "####################################################################################"
        echo "#    You need dracut.conf in /etc/dracut.conf.d/ for the initramfs flag to work    #"
        echo "# Using the tree flag with USE '-binary -initramfs', will put one in place for you #"
        echo "####################################################################################"
	## need a kill option if this dose not exist
   fi
}

src_install() {
        unset KBUILD_OUTPUT
   if use tree; then
	rsync -ar ${S}/${SLOT}/tree/ ${D}
   fi
   if use backup; then
        ## this is more hackery to test dracut in the ebuild quick, give this build "USE" of "-bina>
        ## this also needs a full run for parts to be put in place, Im not going to say other wise >
        mkdir -p ${D}/boot/EFI/Gentoo
        cp /boot/EFI/Gentoo/*hardened1 ${D}/boot/EFI/Gentoo
        cp /boot/EFI/Gentoo/*.img ${D}/boot/EFI/Gentoo
        mkdir -p ${CERTSDIR_NEW}
        mkdir -p ${USR_SRC_BUILD}
        rsync -ar ${S}/certs/ ${CERTSDIR_NEW} || die "cd failed 4"
        mkdir -p ${LIB_MODULES}/{build,source,kernel}
        rsync -ar ${WORKDIR}/${KERNELTAGS}/ ${LIB_MODULES}
        mkdir -p ${D}/usr/src/linux-${KERNELTAG}
        rsync -ar ${S}/ ${D}/usr/src/linux-${KERNELTAG}
        ln -sf ${D}/usr/src/linux-${KERNELTAG} ${USR_SRC_BUILD}
        ln -sf ${D}/usr/src/linux-${KERNELTAG} ${D}/usr/src/linux
   fi
   if use ?; then
	# TODO: Change to SANDBOX_WRITE=".." for installkernel writes
	#### "DONT:" Disable sandbox, that is a sandbox violation
	#### "export SANDBOX_ON=0"

	## so far everthing has been made in "${S}" and would have to think on if there is a batter way to set all this up more orginized
	## There is still loose ends that need put in place that where causing fault
	## "${D}" is the image directory and is where the mirror for the file system is built
	## "${EROOT}" is where ever portage is cd'ed to and "${ROOT}" is a sandbox violation
	## Using "${EROOT}" past src_instal, is ="${ROOT}" thats also a sandbox violation
	## This is a custom kernel and proper note needs made as to where things are getting made so that the build will not be incomplete
        mkdir -p ${D}/boot/EFI/Liguros || die
        rsync -ar ${S}/certs/ ${CERTSDIR_NEW} || die "cd failed 4"


	rsync -ar ${S}\ ${D}/usr/src/linux-${KERNELTAG}

	if use symlink; then
		ln -sf ${D}/usr/src/linux-${KERNELTAG} ${D}/usr/src/linux
	fi
   fi

   if use tree; then
        rsync -ar ${FILESDIR}/tree/ ${D}
   fi



   if use initramfs; then
	## this is where dracut must be ran to pervent a sandbox violation
        ## dracut will make /usr/src/linux from /lib/modules/${KERNELTAGS}/build, there is no need for hackery to do what installkernel and dracut do
        ## this is all I could get dracut to run and in this order for some reason, it dose not respect the compreshion type I give it the way it was
        einfo "Config is needed in "
        einfo ">>> Dracut: building initramfs"
        cd ${USR_SRC_BUILD}
        dracut \
        -v \
        --compress=zstd \
        --stdlog=5 \
        --force \
        --kver 6.1.124-debian1 \
        --kmoddir ${LIB_MODULES} \
        --fwdir /lib/firmware \
        --early-microcode \
        --libdirs "/lib64 /lib /usr/lib /usr/lib64" \
        --add-fstab /etc/fstab \
        --fstab \
        --lvmconf \
        ${D}/efi/EFI/Liguros/initramfs-${KERNELTAGS}.img ${KERNELTAGS} || die ">>>Dracut: Building initramfs failed"
   fi

   if use initramfs13; then
	# NOTE: WIP and not well tested yet.
	# The initramfs will be configurable via USE, i.e.
	# USE=zfs will pass '--zfs' to Dracut
	# USE=-systemd will pass '--omit dracut-systemd systemd systemd-networkd systemd-initrd' to exclude these (Dracut) modules from the initramfs.
	## this all is too much to ask portage to do in one go, dracut keep taking a dump and would stop accepting commands
        #
	# NOTE 2: this will create a fairly.... minimal, and modular initramfs. It has been tested with things with ZFS and LUKS, and 'works'.
	# Things like network support have not been tested (I am currently unsure how well this works with Gentoo Linux based systems),
        # and may end up requiring networkmanager for decent support (this really needs further research).
        ## " network-legacy " works but " network-manager " needs " systemd " to work, "NOTE" the trailing spaces that are needed for add and omit
        ## " base rootfs-block udev-rules shutdown " had to be put in the omit list to get openrc to work on a gentoo backup
        ## udev dose not have time to symlink all items to "/dev/disk/*" and will cause a crash to dracut shell on boot
        ## use "PARTUUID" instead of "UUID" in "/etc/fstab", to get it to boot  and had to manualy edit "grub.cfg" to get gentoo to use this kernel
        ## dont know what is up with dracut on my end, but kept taking a dump after so many variables and could not get these all to run with out failer

	###########################
	# installkernel can do this
	${@}=50-dracut.install
	${@}=51-dracut-rescue.install
	#############################

        $(usex btrfs "-a btrfs" "-o btrfs") \
        $(usex dmraid "-a dmraid -a dm" "-o dmraid") \
        $(usex hardened "-o resume" "-a resume") \
        $(usex iscsi "-a iscsi" "-o iscsi") \
        $(usex lvm "-a lvm -a dm" "-o lvm") \
        $(usex lvm "--lvmconf" "--nolvmconf") \
        $(usex luks "-a crypt" "-o crypt") \
        $(usex mdadm "--mdadmconf" "--nomdadmconf") \
        $(usex mdadm "-a mdraid" "-o mdraid") \
        $(usex microcode "--early-microcode" "--no-early-microcode") \
        $(usex multipath "-a multipath -a dm" "-o multipath") \
        $(usex nbd "-a nbd" "-o nbd") \
        $(usex nfs "-a nfs" "-o nfs") \
        $(usex plymouth "-a plymouth" "-o plymouth") \
        $(usex selinux "-a selinux" "-o selinux") \
        $(usex systemd "-a systemd -a systemd-initrd -a systemd-networkd" "-o systemd -o systemd-initrd -o systemd-networkd") \
        $(usex zfs "-a zfs" "-o zfs") \
        $(usex NetworkManager) \
        ## these as well gave issue but I reduced them in full to a config file, to solve the issues given
        ## the above might work in conjunction with the config file, but not doing any more testing of dracut since got a working kernel
        ## dracut needs " systemd " for " uefi-stub ", so dracut will be removed and replaced by mkinitramfs instead to get efi-stub
        --add "base fs-lib i18n kernel-modules modsign NetworkManager qemu qemu-net rootfs-block shutdown terminfo uefi-lib udev-rules usrmount" \
        --omit "memstrack biosdevname bootchart busybox caps convertfs dash debug dmsquash-live dmsquash-live-ntfs fcoe fcoe-uefi fstab-sys gensplash ifcfg img-lib livenet network-legacy mksh rpmversion securityfs ssh-client stratis syslog url-lib" \


        # if USE=symlink...
	# Dracut makes this dir and this command shound not go before

    fi
        mkdir -p ${D_FILESDIR}
	cp -a ${PORTAGE_BUILDDIR}/temp/build.log ${D_FILESDIR}

        ## at this point the image tree should have these if everthing worked
        ## "/lib/modules/${KERNELTAGS}/" should have the modules
        ## "/lib/modules/${KERNELTAGS}/build" should have the build tree
        ## "/lib/modules/${KERNELTAGS}/source" should have the source tree
        ## "/lib/modules/${KERNELTAGS}/kernel" should have the kernel tree
        ## "/etc/kernel/certs/${KERNELTAGS}" should have the certification made
        ## "/boot" or "/boot/EFI/Liguros" should have boot files, need a if else check to give these as option choice based on efi
        ## uncheek this this to stop the build so verification can be had that all is done
}

pkg_postinst() {

   if use initramfs; then

        einfo ""
        einfo ">>> Dracut: Finished building initramfs"
        ewarn ""
        ewarn "WARNING... WARNING... WARNING..."
        ewarn ""
        ewarn "Dracut initramfs has been generated!"
        ewarn ""
        ewarn "Required kernel arguments:"
        ewarn ""
        ewarn "    root=/dev/ROOT"
        ewarn ""
        ewarn "    Where ROOT is the device node for your root partition as the"
        ewarn "    one specified in /etc/fstab"
        ewarn ""
        ewarn "Additional kernel cmdline arguments that *may* be required to boot properly..."
        ewarn ""
        ewarn "If you use hibernation:"
        ewarn ""
        ewarn "    resume=/dev/SWAP"
        ewarn ""
        ewarn "    Where $SWAP is the swap device used by hibernate software of your choice."
        ewarn""
        ewarn "    Please consult 'man 7 dracut.kernel' for additional kernel arguments."
   fi

}
