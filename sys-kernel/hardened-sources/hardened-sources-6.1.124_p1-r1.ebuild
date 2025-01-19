# Copyright 2020-2023 Liguros Authors
# Distributed under the terms of the GNU General Public License v2
EAPI=8

inherit check-reqs mount-boot toolchain-funcs

DESCRIPTION="Linux kernel sources with Debian patches."
HOMEPAGE="https://packages.debian.org/unstable/kernel/"
LICENSE="GPL-2"
KEYWORDS="x86 amd64 arm arm64"

SLOT=$(ver_cut 1-2)

RESTRICT="binchecks strip mirror"

IUSE="binary btrfs clang custom-cflags debug dmraid dtrace ec2 firmware hardened iscsi libressl luks lvm mcelog mdadm microcode multipath nbd nfs plymouth selinux sign-modules symlink systemd wireguard zfs"

REQUIRED_USE="hardened"

BDEPEND="
	sys-devel/bc
	debug? ( dev-util/dwarves )
	virtual/libelf
"

DEPEND="
	net-misc/dhcp[client]
	binary? (
		sys-kernel/dracut
		dev-util/pahole
		)
	btrfs? ( sys-fs/btrfs-progs )
	dtrace? (
		dev-util/dtrace-utils
		dev-libs/libdtrace-ctf
	)
	firmware? (
		sys-kernel/linux-firmware
	)
	luks? ( sys-fs/cryptsetup )
	lvm? ( sys-fs/lvm2 )
	mdadm? ( sys-fs/mdadm )
	mcelog? ( app-admin/mcelog )
	plymouth? (
		x11-libs/libdrm
		sys-boot/plymouth[udev]
	)
	sign-modules? (
		|| ( dev-libs/openssl
		     dev-libs/libressl
        )
		sys-apps/kmod
	)
	systemd? ( sys-apps/systemd )
	!systemd? ( sys-fs/mdevd )
	wireguard? ( virtual/wireguard )
	zfs? ( sys-fs/zfs )
"

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

DEB_PV="${DEB_PV_BASE}${DEB_EXTRAVERSION}"
KERNEL="linux_${DEB_PV_BASE}.orig.tar.xz"
DEB_PATCH="linux_${DEB_PV}.debian.tar.xz"
KERNEL_ARCHIVE="https://www.dropbox.com/scl/fi/4llspk9xzmmcvwn9h00b2/linux_6.1.124.orig.tar.xz?rlkey=mkje9nitinqzx9tbmv9q5ggk9&st=a8g9mz06&raw=1 -> ${KERNEL}"
DEB_PATCH_ARCHIVE="https://www.dropbox.com/scl/fi/bfuyprfhj7cq17dzbruqf/linux_6.1.124-1.debian.tar.xz?rlkey=44pi91kwxa6v8mpnj5i8rcw0n&st=mmnekdpy&raw=1 -> ${DEB_PATCH}"
DEB_DSC_ARCHIVE="https://www.dropbox.com/scl/fi/t6ee945301xzlip1msbeo/linux_6.1.124-1.dsc?rlkey=0n9p6vw46xoya095zpwhztyy6&st=px0scfzu&raw=1 -> linux_${DEB_PV}.dsc"
BUILD_PATCH="/var/git/liguros-xxx/sys-kernel/hardened-sources/patch-files/"

DISTDIR=/var/cache/portage/distfiles/

SRC_URI="
        ${KERNEL_ARCHIVE}
        ${DEB_PATCH_ARCHIVE}
        ${DEB_DSC_ARCHIVE}
"

SRC_DIR="
	${GRAPHENE_PATCH}
	${GENTOO_PATCH}
"

S="${WORKDIR}/linux-${DEB_PV_BASE}"

FILESDIR="/var/tmp/portage/sys-kernel/hardened-sources-6.1.124_p1-r1/files"

# TODO: manage HARDENED_PATCHES and GENTOO_PATCHES can be managed in a git repository and packed into tar balls per version.



GRAPHENE_PATCHES_DIR="${WORKDIR}/${SLOT}/graphene-patches/"

# This is a patch set to patch the debian patches so can use a graphene hardened LTS source fork instead of a hardened patch set #
# This source requies the hardened flag and not sure on a and/or statement to give the debian source with out that flag enabled  #
# That is why the hardened flag is set to required right now and more would need done to this ebuild to change that flags state  #

GRAPHENE_PATCHES=(
    0000-debian-gitignore-series.patch # Brakes build tree if edited #
    0001-giving-blank-patches-something-to-do.patch #0#+8
    0002-firmware-remove-redundant-log-messages-from-drivers-patch.patch
    0003-wifi-mt76-do-not-run-mt76_unregister_device-on-unregistered-hw-patch.patch #1#-8
    0004-fs-enable-link-security-restrictions-by-default-patch.patch #2#+10
    0005-add-sysctl-to-disallow-unprivileged-CLONE_NEWUSER-by-default-patch.patch #3#-10
    0006-security-perf-allow-further-restriction-of-perf_event_open-patch.patch
    0007-efi-lock-down-the-kernel-if-booted-in-secure-boot-mo-patch.patch
    0008-netfilter-nf_tables-deactivate-anonymous-set-from-pr-patch.patch #5#-4
    0009-intel-iommu-add-kconfig-option-to-exclude-igpu-by-default-patch.patch
    0010-x86-make-x32-syscall-support-conditional-patch.patch
    0011-arm64-dts-rockchip-Enable-GPU-on-SOQuartz-CM4-patch.patch #4#+4
)

GENTOO_PATCHES_DIR="${WORKDIR}/${SLOT}/gentoo-patches/"

# Gentoo Linux 'genpatches' patch set
# 1510_fs-enable-link-security-restrctions-by-default.patch is already provided in debian patches
# 4567_distro-Gentoo-Kconfig TODO?
# Graphene source fixed 2900, 2930,

GENTOO_PATCHES=(
    1500_XATTR_USER_PREFIX.patch
#    1510_fs-enable-link-security-restrictions-by-default.patch
    1700_sparc-address-warray-bound-warnings.patch
    2000_BT-Check-key-sizes-only-if-Secure-Simple-Pairing-enabled.patch
    2010_Fix_randomize_layout_crash_in_struct_neigh.patch
    2600_HID-revert-Y900P-fix-ThinkPad-L15-touchpad.patch
#    2900_tmp513-Fix-build-issue-by-selecting-CONFIG_REG.patch
    2910_bfp-mark-get-entry-ip-as--maybe-unused.patch
    2920_sign-file-patch-for-libressl.patch
#    2930_gcc-plugins-Reorg-gimple-incs-for-gcc-13.patch
    2950_kbuild-CRC32-1MB-dict-xz-modules.patch
    3000_Support-printing-firmware-info.patch
    4567_distro-Gentoo-Kconfig.patch
    5000_shiftfs-6.1.patch
    5010_enable-cpu-optimizations-universal.patch
)


DTRACE_PATCHES_DIR="${WORKDIR}/${SLOT}/dtrace-patches"

DTRACE_PATCHES=(
    0001-kallsyms-new-proc-kallmodsyms-with-builtin-modules-a.patch
    0002-ctf-generate-CTF-information-for-the-kernel.patch
    0003-waitfd-new-syscall-implementing-waitpid-over-fds.patch
    0004-ctf-kernel-build-with-gt-for-CTF-generation-using-GC.patch
    0005-ctf-toolchain-based-CTF-support.patch
    0006-kbuild-arm64-Set-objects.builtin-dependency-to-Image.patch
    0007-ctf-adapt-to-the-new-CTF-linker-API.patch
    0008-ctf-discard-CTF-sections-for-arches-not-using-DISCAR.patch
    0009-ctf-discard-CTF-from-the-vDSO.patch
    0010-ctf-fix-memory-leak-in-ctfarchive.patch
    0011-ctf-adjust-to-upcoming-binutils-ctf_link_add_ctf-API.patch
    0012-ctf-support-ld-ctf-variables-if-available.patch
    0013-ctf-add-.ctf-to-.gitignore.patch
    0014-waitfd-enable-by-default.patch
)

eapply_graphene() {
        eapply "${GRAPHENE_PATCHES_DIR}${1}"
}

eapply_gentoo() {
	eapply "${GENTOO_PATCHES_DIR}${1}"
}

eapply_dtrace() {
	eapply "${DTRACE_PATCHES_DIR}${1}"
}

get_patch_list() {
	[[ -z "${1}" ]] && die "No patch series file specified"
	local patch_series="${1}"
	while read line ; do
		if [[ "${line:0:1}" != "#" ]] ; then
			echo "${line}"
		fi
	done < "${patch_series}"
}

get_certs_dir() {
	# find a certificate dir in /etc/kernel/certs/ that contains signing cert for modules.
	for subdir in $PF $P linux; do
		certdir=/etc/kernel/certs/$subdir
		if [ -d $certdir ]; then
			if [ ! -e $certdir/signing_key.pem ]; then
				eerror "$certdir exists but missing signing key; exiting."
				exit 1
			fi
			echo $certdir
			return
		fi
	done
}

pkg_pretend() {
	# Ensure we have enough disk space to compile
	if use binary ; then
		CHECKREQS_DISK_BUILD="5G"
		check-reqs_pkg_setup
	fi
}

pkg_setup() {
	export REAL_ARCH="$ARCH"
	unset ARCH; unset LDFLAGS #will interfere with Makefile if set
}

src_unpack() {
        # unpack the kernel sources
        unpack ${KERNEL} || die "failed to unpack kernel sources"

	# unpack the kernel patches
        unpack ${DEB_PATCH} || die "failed to unpack debian patches"

	# Patches to graphene source
        mkdir ${SLOT}
        mkdir ${GENTOO_PATCHES_DIR}
        mkdir ${GRAPHENE_PATCHES_DIR}
        mkdir ${DTRACE_PATCHES_DIR}

	# Cant figure out the right syntex to make this proper #
#	cp -ar ${BUILD_PATCH}\${SLOT}\* ${SLOT} || die "failed to copy patches"
	cp -ar /var/git/liguros-xxx/sys-kernel/hardened-sources/patch-files/6.1/* ${SLOT} || die "failed to copy patch"
}

src_prepare() {
	debug-print-function ${FUNCNAME} "${@}"
#        cd ${S}

	### PATCHES ###
	cd ${WORKDIR}
        dir
        # only apply these if USE=hardened as the patches will break proprietary userspace and some others.
        # apply hardening patches
        einfo "Applying graphene patches ..."
        for my_patch in ${GRAPHENE_PATCHES[*]}; do
            eapply_graphene "${my_patch}"
        done

        # copy the debian patches into the kernel sources work directory (config-extract and graphene patches requires this).
        #cp -ra "${WORKDIR}"/debian "${S}"/debian 

        cd ${S}

        # copy the debian patches into the kernel sources work directory (config-extract requires this).
#	cp -raf "${S}"/debian "${WORKDIR}"

	# apply debian patches
	for debpatch in $( get_patch_list "${WORKDIR}/debian/patches/series" ); do
		eapply -p1 "${WORKDIR}/debian/patches/${debpatch}"
	done

	# apply gentoo patches
	einfo "Applying Gentoo Linux patches ..."
	for my_patch in ${GENTOO_PATCHES[*]} ; do
        eapply_gentoo "${my_patch}"
	done

	# optionally apply dtrace patches
	if use dtrace; then
        for my_patch in ${DTRACE_PATCHES[*]} ; do
            eapply_dtrace "${my_patch}"
        done
    fi

#	cd ${S}

	# append EXTRAVERSION to the kernel sources Makefile
	sed -i -e "s:^\(EXTRAVERSION =\).*:\1 ${MODULE_EXT}:" Makefile || die "failed to append EXTRAVERSION to kernel Makefile"

	# todo: look at this, haven't seen it used in many cases.
	sed	-i -e 's:#export\tINSTALL_PATH:export\tINSTALL_PATH:' Makefile || die "failed to fix-up INSTALL_PATH in kernel Makefile"
        # copy the debian patches into the kernel sources work directory (config-extract requires this).
        cp -a "${WORKDIR}"/debian "${S}"/debian

        # punt the debian devs certificates
        rm -rf "${S}"/debian/certs


	### GENERATE CONFIG ###

	local arch featureset subarch
	featureset="standard"
	if [[ ${REAL_ARCH} == x86 ]]; then
		arch="i386"
		subarch="686-pae"
	elif [[ ${REAL_ARCH} == amd64 ]]; then
		arch="amd64"
		subarch="amd64"
	elif [[ ${REAL_ARCH} == arm ]]; then
		arch="armhf"
		subarch="armmp"
	elif [[ ${REAL_ARCH} == arm64 ]]; then
		arch="arm64"
		subarch="arm64"
	else
	    die "Architecture not handled in ebuild"
	fi

	# Copy 'config-extract' tool to the work directory 
	cp "${FILESDIR}"/config-extract-6.1 ./config-extract || die

	# ... and make it executable
	chmod +x config-extract || die

	# ... and now extract the kernel config file!
	./config-extract ${arch} ${featureset} ${subarch} || die

	### TWEAK CONFIG ###
	# Do not configure Debian devs certificates
	echo 'CONFIG_SYSTEM_TRUSTED_KEYS=""' >> .config

	# enable IKCONFIG so that /proc/config.gz can be used for various checks
	# TODO: Maybe not a good idea for USE=hardened, look into this...
	echo "CONFIG_IKCONFIG=y" >> .config
	echo "CONFIG_IKCONFIG_PROC=y" >> .config

	if use custom-cflags; then
            MARCH="$(python -c "import portage; print(portage.settings[\"CFLAGS\"])" | sed 's/ /\n/g' | grep "march")"
            if [ -n "$MARCH" ]; then
                    sed -i -e 's/-mtune=generic/$MARCH/g' arch/x86/Makefile || die "Canna optimize this kernel anymore, captain!"
            fi
    fi

	# only enable debugging symbols etc if USE=debug...
	if use debug; then
        echo "CONFIG_DEBUG_INFO=y" >> .config
    else
        echo "CONFIG_DEBUG_INFO=n" >> .config
	sed -i -e "s/^CONFIG_DEBUG\(.*\)=.*/CONFIG_DEBUG\1=n/g" .config
    fi

	if use dtrace; then
        echo "CONFIG_WAITFD=y" >> .config
    fi

	# these options should already be set, but are a hard dependency for ec2, so we ensure they are set if USE=ec2
	if use ec2; then
	    echo "CONFIG_BLK_DEV_NVME=y" >> .config
	    echo "CONFIG_XEN_BLKDEV_FRONTEND=m" >> .config
	    echo "CONFIG_XEN_BLKDEV_BACKEND=m" >> .config
	    echo "CONFIG_IXGBEVF=m" >> .config
	fi

	# hardening opts
	# TODO: document these
	if use hardened; then
        echo "CONFIG_AUDIT=y" >> .config
        echo "CONFIG_EXPERT=y" >> .config
        echo "CONFIG_SLUB_DEBUG=y" >> .config
        echo "CONFIG_SLAB_MERGE_DEFAULT=n" >> .config
        echo "CONFIG_SLAB_FREELIST_RANDOM=y" >> .config
        echo "CONFIG_SLAB_FREELIST_HARDENED=y" >> .config
        echo "CONFIG_SLAB_CANARY=y" >> .config
        echo "CONFIG_SHUFFLE_PAGE_ALLOCATOR=y" >> .config
        echo "CONFIG_RANDOMIZE_BASE=y" >> .config
        echo "CONFIG_RANDOMIZE_MEMORY=y" >> .config
        echo "CONFIG_HIBERNATION=n" >> .config
        echo "CONFIG_HARDENED_USERCOPY=y" >> .config
        echo "CONFIG_HARDENED_USERCOPY_FALLBACK=n" >> .config
        echo "CONFIG_FORTIFY_SOURCE=y" >> .config
        echo "CONFIG_STACKPROTECTOR=y" >> .config
        echo "CONFIG_STACKPROTECTOR_STRONG=y" >> .config
        echo "CONFIG_ARCH_MMAP_RND_BITS=32" >> .config
        echo "CONFIG_ARCH_MMAP_RND_COMPAT_BITS=16" >> .config
        echo "CONFIG_INIT_ON_FREE_DEFAULT_ON=y" >> .config
        echo "CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y" >> .config
        echo "CONFIG_SLAB_SANITIZE_VERIFY=y" >> .config
        echo "CONFIG_PAGE_SANITIZE_VERIFY=y" >> .config

        # gcc plugins
        if ! use clang; then
            echo "CONFIG_GCC_PLUGINS=y" >> .config
            echo "CONFIG_GCC_PLUGIN_LATENT_ENTROPY=y" >> .config
            echo "CONFIG_GCC_PLUGIN_STRUCTLEAK=y" >> .config
            echo "CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL=y" >> .config
            echo "CONFIG_GCC_PLUGIN_STACKLEAK=y" >> .config
            echo "CONFIG_STACKLEAK_TRACK_MIN_SIZE=100" >> .config
            echo "CONFIG_STACKLEAK_METRICS=n" >> .config
            echo "CONFIG_STACKLEAK_RUNTIME_DISABLE=n" >> .config
            echo "CONFIG_GCC_PLUGIN_RANDSTRUCT=y" >> .config
            echo "CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE=n" >> .config
        fi

        # main hardening options complete... anything after this point is a focus on disabling potential attack vectors
        # i.e legacy drivers, new complex code that isn't yet proven, or code that we really don't want in a hardened kernel.
        echo 'CONFIG_KEXEC=n' >> .config
        echo "CONFIG_KEXEC_FILE=n" >> .config
        echo 'CONFIG_KEXEC_SIG=n' >> .config
    fi

	# mcelog is deprecated, but there are still some valid use cases and requirements for it... so stick it behind a USE flag for optional kernel support.
	if use mcelog; then
        echo "CONFIG_X86_MCELOG_LEGACY=y" >> .config
    fi

	# sign kernel modules via
	if use sign-modules; then
        certs_dir=$(get_certs_dir)
        echo
		if [ -z "$certs_dir" ]; then
			eerror "No certs dir found in /etc/kernel/certs; aborting."
			die
		else
			einfo "Using certificate directory of $certs_dir for kernel module signing."
		fi
		echo
        # turn on options for signing modules.
        # first, remove existing configs and comments:
        echo 'CONFIG_MODULE_SIG=""' >> .config
        # now add our settings:
        echo 'CONFIG_MODULE_SIG=y' >> .config
        echo 'CONFIG_MODULE_SIG_FORCE=n' >> .config
        echo 'CONFIG_MODULE_SIG_ALL=n' >> .config
        # LibreSSL currently (2.9.0) does not have CMS support, so is limited to SHA1.
        # https://bugs.gentoo.org/706086
        # https://bugzilla.kernel.org/show_bug.cgi?id=202159
        if use libressl; then
            echo 'CONFIG_MODULE_SIG_HASH="sha1"' >> .config
        else
            echo 'CONFIG_MODULE_SIG_HASH="sha512"' >> .config
        fi
        echo 'CONFIG_MODULE_SIG_KEY="${certs_dir}/signing_key.pem"' >> .config
        echo 'CONFIG_SYSTEM_TRUSTED_KEYRING=y' >> .config
        echo 'CONFIG_SYSTEM_EXTRA_CERTIFICATE=y' >> .config
        echo 'CONFIG_SYSTEM_EXTRA_CERTIFICATE_SIZE="4096"' >> .config

        # See above comment re: LibreSSL
        if use libressl; then
            echo "CONFIG_MODULE_SIG_SHA1=y" >> .config
        else
            echo "CONFIG_MODULE_SIG_SHA512=y" >> .config
        fi
        ewarn "This kernel will ALLOW non-signed modules to be loaded with a WARNING."
        ewarn "To enable strict enforcement, YOU MUST add module.sig_enforce=1 as a kernel boot"
        ewarn "parameter (to params in /etc/boot.conf, and re-run boot-update.)"
        echo
    fi

	# enable wireguard support within kernel
	if use wireguard; then
        echo 'CONFIG_WIREGUARD=m' >> .config
        # there are some other options, but I need to verify them first, so I'll start with this
    fi

	# get config into good state:
	yes "" | make oldconfig >/dev/null 2>&1 || die
	cp .config "${T}"/.config || die
	make -s mrproper || die "make mrproper failed"

	# Apply any user patches
	eapply_user
}

src_configure() {
	if use binary; then

        debug-print-function ${FUNCNAME} "${@}"

        tc-export_build_env
        MAKEARGS=(
            V=1

            HOSTCC="$(tc-getBUILD_CC)"
            HOSTCXX="$(tc-getBUILD_CXX)"
            HOSTCFLAGS="${BUILD_CFLAGS}"
            HOSTLDFLAGS="${BUILD_LDFLAGS}"

            CROSS_COMPILE=${CHOST}-
            AS="$(tc-getAS)"
            CC="$(tc-getCC)"
            LD="$(tc-getLD)"
            AR="$(tc-getAR)"
            NM="$(tc-getNM)"
            STRIP=":"
            OBJCOPY="$(tc-getOBJCOPY)"
            OBJDUMP="$(tc-getOBJDUMP)"

            # we need to pass it to override colliding Gentoo envvar
            ARCH=$(tc-arch-kernel)
        )

        mkdir -p "${WORKDIR}"/modprep || die
        cp "${T}"/.config "${WORKDIR}"/modprep/ || die
        emake O="${WORKDIR}"/modprep "${MAKEARGS[@]}" olddefconfig || die "kernel configure failed"
        emake O="${WORKDIR}"/modprep "${MAKEARGS[@]}" modules_prepare || die "modules_prepare failed"
        cp -pR "${WORKDIR}"/modprep "${WORKDIR}"/build || die
    fi
}

src_compile() {
	if use binary; then
        debug-print-function ${FUNCNAME} "${@}"

        emake O="${WORKDIR}"/build "${MAKEARGS[@]}" all || "kernel build failed"
    fi
}

src_install() {
	debug-print-function ${FUNCNAME} "${@}"

	# TODO: Change to SANDBOX_WRITE=".." for installkernel writes
	# Disable sandbox
	export SANDBOX_ON=0

	# copy sources into place:
	dodir /usr/src
	cp -a "${S}" "${D}"/usr/src/linux-${DEB_PV_BASE}${MODULE_EXT} || die "failed to install kernel sources"
	cd "${D}"/usr/src/linux-${DEB_PV_BASE}${MODULE_EXT}

	# prepare for real-world use and 3rd-party module building:
	make mrproper || die
	cp "${T}"/.config .config || die
	cp -a "${WORKDIR}"/debian debian || die

	# if we didn't use genkernel, we're done. The kernel source tree is left in
	# an unconfigured state - you can't compile 3rd-party modules against it yet.
	if use binary; then
        make prepare || die
        make scripts || die

        local targets=( modules_install )

        # ARM / ARM64 requires dtb
        if (use arm || use arm64); then
                targets+=( dtbs_install )
        fi

        emake O="${WORKDIR}"/build "${MAKEARGS[@]}" INSTALL_MOD_PATH="${ED}" INSTALL_PATH="${ED}/boot" "${targets[@]}"
        installkernel "${DEB_PV_BASE}${MODULE_EXT}" "${WORKDIR}/build/arch/x86_64/boot/bzImage" "${WORKDIR}/build/System.map" "${EROOT}/boot"

        # module symlink fix-up:
        rm -rf "${D}"/lib/modules/${DEB_PV_BASE}${MODULE_EXT}/source || die "failed to remove old kernel source symlink"
        rm -rf "${D}"/lib/modules/${DEB_PV_BASE}${MODULE_EXT}/build || die "failed to remove old kernel build symlink"

        # Set-up module symlinks:
        ln -s /usr/src/linux-${PV}-${TEMP_EXTRA_VERSION} "${D}"/lib/modules/${DEB_PV_BASE}${MODULE_EXT}/source || die "failed to create kernel source symlink"
        ln -s /usr/src/linux-${PV}-${TEMP_EXTRA_VERSION} "${D}"/lib/modules/${DEB_PV_BASE}${MODULE_EXT}/build || die "failed to create kernel build symlink"

        # Fixes FL-14
        cp "${WORKDIR}/build/System.map" "${D}"/usr/src/linux-${DEB_PV_BASE}${MODULE_EXT}/ || die "failed to install System.map"
        cp "${WORKDIR}/build/Module.symvers" "${D}"/usr/src/linux-${DEB_PV_BASE}${MODULE_EXT}/ || die "failed to install Module.symvers"

        if use sign-modules; then
            for x in $(find "${D}"/lib/modules -iname *.ko); do
                # $certs_dir defined previously in this function.
                ${WORKDIR}/build/scripts/sign-file sha512 $certs_dir/signing_key.pem $certs_dir/signing_key.x509 $x || die
            done
            # install the sign-file executable for future use.
            exeinto /usr/src/linux-${PV}-${P}/scripts
            doexe ${WORKDIR}/build/scripts/sign-file
        fi
    fi
}

pkg_postinst() {

	# TODO: Change to SANDBOX_WRITE=".." for Dracut writes
	export SANDBOX_ON=0

	# if USE=symlink...
	if use symlink; then
	    # delete the existing symlink if one exists
	    if [[ -h "${EROOT}"/usr/src/linux ]]; then
            rm "${EROOT}"/usr/src/linux
        fi
        # and now symlink the newly installed sources
	    ewarn ""
	    ewarn "WARNING... WARNING... WARNING"
	    ewarn ""
	    ewarn "/usr/src/linux symlink automatically set to linux-${DEB_PV_BASE}${MODULE_EXT}"
	    ewarn ""
		ln -sf "${EROOT}"/usr/src/linux-${DEB_PV_BASE}${MODULE_EXT} "${EROOT}"/usr/src/linux
	fi

	# if there's a modules folder for these sources, generate modules.dep and map files
	if [[ -d ${EROOT}/lib/modules/${DEB_PV_BASE}${MODULE_EXT} ]]; then
		depmod -a ${DEB_PV_BASE}${MODULE_EXT}
	fi

	# NOTE: WIP and not well tested yet.
	#
	# Dracut will build an initramfs when USE=binary.
	#
	# The initramfs will be configurable via USE, i.e.
	# USE=zfs will pass '--zfs' to Dracut
	# USE=-systemd will pass '--omit dracut-systemd systemd systemd-networkd systemd-initrd' to exclude these (Dracut) modules from the initramfs.
	#
	# NOTE 2: this will create a fairly.... minimal, and modular initramfs. It has been tested with things with ZFS and LUKS, and 'works'.
	# Things like network support have not been tested (I am currently unsure how well this works with Gentoo Linux based systems),
	# and may end up requiring network-manager for decent support (this really needs further research).
	if use binary; then
	    einfo ""
        einfo ">>> Dracut: building initramfs"
        dracut \
        --stdlog=5 \
        --force \
        --no-hostonly \
        --add "base fs-lib i18n kernel-modules network qemu qemu-net rootfs-block shutdown terminfo udev-rules usrmount" \
        --omit "biosdevname bootchart busybox caps convertfs dash debug dmsquash-live dmsquash-live-ntfs fcoe fcoe-uefi fstab-sys gensplash ifcfg img-lib livenet mksh network-manager rpmversion securityfs ssh-client stratis syslog url-lib" \
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
        --kmoddir ${EROOT}/lib/modules/${DEB_PV_BASE}${MODULE_EXT} \
        --fwdir ${EROOT}/lib/firmware \
        "${EROOT}"/boot/initrd-${DEB_PV_BASE}${MODULE_EXT} ${DEB_PV_BASE}${MODULE_EXT} || die ">>>Dracut: Building initramfs failed"
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
        ewarn "    Please consult "man 7 dracut.kernel" for additional kernel arguments."
	fi

	# warn about the issues with running a hardened kernel
	if use hardened; then
        ewarn ""
        ewarn "WARNING... WARNING... WARNING..."
        ewarn ""
        ewarn "Hardened patches have been applied to the kernel and KCONFIG options have been set."
        ewarn "These KCONFIG options and patches change kernel behavior."
        ewarn "Changes include:"
        ewarn "Increased entropy for Address Space Layout Randomization"
        ewarn "GCC plugins (if using GCC)"
        ewarn "Memory allocation"
        ewarn "... and more"
        ewarn ""
        ewarn "These changes will stop certain programs from functioning"
        ewarn "e.g. VirtualBox, Skype"
        ewarn "Full information available in $DOCUMENTATION"
        ewarn ""
    fi

	# if there are out-of-tree kernel modules detected, warn warn warn
	# TODO: tidy up below
	if use binary && [[ -e "${EROOT}"/var/lib/module-rebuild/moduledb ]]; then
	    ewarn ""
		ewarn "WARNING... WARNING... WARNING..."
		ewarn ""
		ewarn "External kernel modules are not yet automatically built"
		ewarn "by USE=binary - emerge @modules-rebuild to do this"
		ewarn "and regenerate your initramfs if you are using ZFS root filesystem"
		ewarn ""
	fi

	if use binary; then
		if [[ -e /etc/boot.conf ]]; then
			ego boot update
		fi
	fi
}
