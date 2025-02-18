# Copyright 2020-2023 Liguros Authors
# Distributed under the terms of the GNU General Public License v2
EAPI=8

inherit check-reqs mount-boot savedconfig toolchain-funcs

DESCRIPTION="Linux kernel sources with Debian patches."
HOMEPAGE="https://packages.debian.org/unstable/kernel/"
LICENSE="GPL-2"
KEYWORDS="x86 amd64 arm arm64"

SLOT=$(ver_cut 1-2)

RESTRICT="binchecks strip mirror"

IUSE="binary btrfs clang custom-cflags debug dtrace dmraid ec2 efi efistub +firmware +hardened iscsi initramfs initramfs13  libressl luks lvm makeconfig  mdadm mcelog +microcode multipath NetworkManager nfs nbd plymouth +savedconfig selinux openssl +sign-modules secureboot symlink systemd qemu wireguard xen zfs tree"

REQUIRED_USE="hardened"

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
	binary? (
                sys-kernel/installkernel
		dev-util/pahole
		sys-fs/squashfs-tools
		lvm? ( sys-kernel/genkernel
		       sys-fs/lvm2[lvm,-thin] )
		)
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

DEB_PV="${DEB_PV_BASE}${DEB_EXTRAVERSION}"
KERNEL="linux_${DEB_PV_BASE}.orig.tar.xz"
DEB_PATCH="linux_${DEB_PV}.debian.tar.xz"
KERNEL_ARCHIVE="https://www.dropbox.com/scl/fi/isqrcpbld7pk6iln2dt6c/linux_6.1.124.orig.tar.xz?rlkey=kdldkzec29i70aq689yoy2yv2&st=toxjojql&dl=0&raw=1 -> ${KERNEL}"
DEB_PATCH_ARCHIVE="https://www.dropbox.com/scl/fi/bfuyprfhj7cq17dzbruqf/linux_6.1.124-1.debian.tar.xz?rlkey=44pi91kwxa6v8mpnj5i8rcw0n&st=mmnekdpy&raw=1 -> ${DEB_PATCH}"
DEB_DSC_ARCHIVE="https://www.dropbox.com/scl/fi/gaia3pyf5fy3uxn12rv34/linux_6.1.124-1.dsc?rlkey=84johlvp7kd8l093pj9knmdtf&st=9biultvi&dl=0&raw=1 -> linux_${DEB_PV}.dsc"
#BUILD_PATCH="/var/git/liguros-xxx/sys-kernel/debian-sources/files/"

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

KERNELTAGS="${DEB_PV_BASE}-debian1"
KERNELTAG="${DEB_PV_BASE}${MODULE_EXT}"
D_FILESDIR="${D}/var/db/repos/liguros-xxx/sys-kernel/debian-sources/files"
PORTAGE_BUILDDIR="/var/tmp/portage/sys-kernel/debian-sources-6.1.124_p1-r1"
USR_SRC_BUILD="${D}/lib/modules/${KERNELTAGS}/build"
USR_SRC_BUILD_EXT="${D}/lib/modules/${KERNELTAGS}/.extra/build"
CERTSDIR_NEW="${D}/etc/kernel/certs/${KERNELTAGS}"
LIB_MODULES="${D}/lib/modules/${KERNELTAGS}"
GRAPHENE_LIST="${S}/${SLOT}/GRAPHENE_LIST"
DEBIAN_LIST="${S}/${SLOT}/DEBIAN_LIST"
GENTOO_LIST="${S}/${SLOT}/GENTOO_LIST"
DTRACE_LIST="${S}/${SLOT}/DTRACE_LIST"

# cairfull using these, becuase can cause a sandbox violation
SAVEDCONFIG="/etc/portage/savedconfig/${CATEGORY}/${PN}"
CERTSDIR="/etc/kernel/certs/${MODULE_EXT}"
CLEAN_LIB="/lib/modules/${KERNELTAGS}"
CLEAN_USR="/usr/src/linux-${KERNELTAG}"



# TODO: manage HARDENED_PATCHES and GENTOO_PATCHES can be managed in a git repository and packed into tar balls per version.

get_certs_dir() {
    if use sign_modules ; then
	# find a certificate dir in /etc/kernel/certs/ that contains signing cert for modules.
	mkdir -p ${CERTSDIR_NEW}
	cp -a ${CERTSDIR} ${CERTSDIR_NEW}
	for subdir in $PF $P linux; do
		if [ -d ${CERTSDIR_NEW} ]; then
			if [ ! -e ${CERTSDIR_NEW}/signing_key.pem ]; then
				eerror "${CERTSDIR_NEW} exists but missing signing key; exiting."
				exit 1
			fi
			echo ${CERTSDIR_NEW}
			return
		fi
	done
   fi
}

pkg_pretend() {
	# Ensure we have enough disk space to compile
	if use binary ; then
		CHECKREQS_DISK_BUILD="10G"
		check-reqs_pkg_setup
	fi
}

pkg_setup() {
   if use binary ; then
        ## this set a reference call for other phases to use for emake
        ENV_SETUP_MAKECONF()
        {
	unset ARCH; unset LDFLAGS #will interfere with Makefile if set
        local HOSTLD="$(tc-getBUILD_LD)"
        if type -P "${HOSTLD}.bfd" &>/dev/null; then
                HOSTLD+=.bfd
        fi
        local LD="$(tc-getLD)"
        if type -P "${LD}.bfd" &>/dev/null; then
                LD+=.bfd
        fi
        tc-export_build_env
        local MAKECONF=(
            V=1

            HOSTCC="$(tc-getBUILD_CC)"
            HOSTCXX="$(tc-getBUILD_CXX)"
            HOSTLD="${HOSTLD}"
	    HOSTAR="$(tc-getBUILD_AR)"
            HOSTCFLAGS="${BUILD_CFLAGS}"
            HOSTLDFLAGS="${BUILD_LDFLAGS}"

            CROSS_COMPILE=${CHOST}-
            AS="$(tc-getAS)"
            CC="$(tc-getCC)"
            LD="$(tc-getLD)"
            AR="$(tc-getAR)"
            NM="$(tc-getNM)"
	    CPP="$(tc-getCPP)"
            STRIP=":"
            OBJCOPY="$(tc-getOBJCOPY)"
            OBJDUMP="$(tc-getOBJDUMP)"
	    READELF="$(tc-getREADELF)"

	    # we need to pass it to override colliding Gentoo envvar
            ARCH="$(tc-arch-kernel)"
                )
        }
   fi
}

src_unpack() {
   if use binary ; then
        # unpack the kernel sources
	unpack ${KERNEL} || die "failed to unpack kernel sources"

	# unpack the kernel patches
        unpack ${DEB_PATCH} || die "failed to unpack debian patches"

	# Patches to graphene source
	rsync -a ${FILESDIR}/${SLOT}/ ${SLOT} || die "failed to copy patch"
   fi
}

src_prepare() {
   if use binary ; then
        ENV_SETUP_MAKECONF
	debug-print-function ${FUNCNAME} ${@}

	mkdir -p ${WORKDIR}/${KERNELTAGS}/source || die
	rsync -ar ${S}/ ${WORKDIR}/${KERNELTAGS}/source || die

	### PATCHES ###

        ## copy the debian patches into the kernel sources work directory (config-extract and graphene patches requires this).
        ## there is no need to punt the debian uefi certification and I put it where needs to be for future copy

	cp -ra ${WORKDIR}/debian/ ${S}/debian
	cp -ra ${WORKDIR}/${SLOT}/ ${S}/${SLOT}
	cp -pR ${S}/debian/certs ${S}/certs || die "cd failed 3"


	dir ${S}/${SLOT}

        cd ${S}

        ## the bloat running these patch in a circle made this ebuild a mess, so I reduced them down to a single line
        ## the patch file list that was dumped into this ebuild and could be done better by moving it to a manifest file
        ## so all the patch files are now in a manifest list to clean up this ebuild 
	if use hardened; then
	einfo "Applying Graphene patches ..."
	        for LIST_A in $( grep ".patch" ${GRAPHENE_LIST}); do eapply ${LIST_A}; done || die "echo failed"

	sleep 5 &&

	einfo "Applying Debian kernel patches ..."
                for LIST_B in $( grep ".patch" ${DEBIAN_LIST}); do eapply ${LIST_B}; done|| die "echo failed"
	fi

	sleep 5 &&

	einfo "Applying Gentoo Linux patches ..."
                for LIST_C in $( grep ".patch" ${GENTOO_LIST}); do eapply ${LIST_C}; done|| die "echo failed"

	sleep 5 &&

	if use dtrace; then
	einfo "Applying Dtrace patches ..."
                for LIST_D in $( grep ".patch" ${DTRACE_LIST}); do eapply ${LIST_D}; done|| die "echo failed"
	fi

#	rm -r ${WORKDIR}/${SLOT}

	if use makeconfig; then
	# append EXTRAVERSION to the kernel sources Makefile
	sed -i -e "s:^\(EXTRAVERSION =\).*:\1 ${MODULE_EXT}:" Makefile || die "failed to append EXTRAVERSION to kernel Makefile"

	# todo: look at this, haven't seen it used in many cases.
	sed	-i -e 's:#export\tINSTALL_PATH:export\tINSTALL_PATH:' Makefile || die "failed to fix-up INSTALL_PATH in kernel Makefile"

	### GENERATE CONFIG ###

	# Copy 'config-extract' tool to the work directory
	cp ${FILESDIR}/config-extract-6.1 ./config-extract || die

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
	        echo "CONFIG_RANDOM_KMALLOC_CACHES=y" >> .config   # this replaces CONFIG_SLAB_CANARY I think
	        echo "CONFIG_SHUFFLE_PAGE_ALLOCATOR=y" >> .config
	        echo "CONFIG_RANDOMIZE_BASE=y" >> .config
	        echo "CONFIG_RANDOMIZE_MEMORY=y" >> .config
	        echo "CONFIG_HIBERNATION=n" >> .config
	        echo "CONFIG_HARDENED_USERCOPY=y" >> .config
#	        echo "CONFIG_HARDENED_USERCOPY_FALLBACK=n" >> .config
	        echo "CONFIG_FORTIFY_SOURCE=y" >> .config
	        echo "CONFIG_STACKPROTECTOR=y" >> .config
	        echo "CONFIG_STACKPROTECTOR_STRONG=y" >> .config
	        echo "CONFIG_ARCH_MMAP_RND_BITS=32" >> .config
	        echo "CONFIG_ARCH_MMAP_RND_COMPAT_BITS=16" >> .config
	        echo "CONFIG_INIT_ON_FREE_DEFAULT_ON=y" >> .config
	        echo "CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y" >> .config
#	        echo "CONFIG_SLAB_SANITIZE_VERIFY=y" >> .config
#	        echo "CONFIG_PAGE_SANITIZE_VERIFY=y" >> .config

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
#        certs_dir=$(${CERTSDIR})
	        echo
			if [ -z "${CERTSDIR_NEW}" ]; then
				eerror "No certs dir found in /etc/kernel/certs; aborting."
				die
			else
				einfo "Using certificate directory of ${CERTSDIR_NEW} for kernel module signing."
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
	        echo 'CONFIG_MODULE_SIG_KEY="${CERTSDIR_NEW}/signing_key.pem"' >> .config
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
	fi
   fi

	# Apply any user patches
	eapply_user

	cd /kill/me || die "It stops"
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
   if use binary ; then
        ENV_SETUP_MAKECONF
        if use initramfs; then
        echo "####################################################################################"
        echo "#    You need dracut.conf in /etc/dracut.conf.d/ for the initramfs flag to work    #"
        echo "# Using the tree flag with USE '-binary -initramfs', will put one in place for you #"
        echo "####################################################################################"
	## need a kill option if this dose not exist
	fi
        if use savedconfig; then
	echo "############################################################################################################"
	echo "# You need .config in /etc/portage/savedconfig/sys-kernel/debian-sources/ for the savedconfig flag to work #"
	echo "#             Using the tree flag with USE '-binary -initramfs', will put one in place for you             #"
	echo "############################################################################################################"
	## need a kill option if this dose not exist
	rm .config
        restore_config .config
                if [ ! -f .config ]; then
                die "Could not locate user configfile, cannot continue"
                fi
	emake ${MAKECONF[@]} olddefconfig || die "kernel configure failed"
        fi
        if use makeconfig; then

	emake ${MAKECONF[@]} oldconfig || die "kernel configure failed"

        fi
	grep "CONFIG_MODULES=y" .config >/dev/null
        RETVAL=$?
        if [ $RETVAL -ne 0 ]; then
                export DO_I_HAVE_MODULES=false
        else
                export DO_I_HAVE_MODULES=true
        fi
   fi
}

src_compile() {
        unset KBUILD_OUTPUT
   if use binary ; then
        ENV_SETUP_MAKECONF
	emake ${MAKECONF[@]} bzImage
        if ${DO_I_HAVE_MODULES}; then
	        emake ${MAKECONF[@]} modules_prepare modules || die "modules_prepare failed"
	fi
        emake ${MAKECONF[@]} all || die "kernel build failed"
   fi
}

src_install() {
        unset KBUILD_OUTPUT
   if use binary ; then
        ENV_SETUP_MAKECONF
	debug-print-function ${FUNCNAME} ${@}

	# TODO: Change to SANDBOX_WRITE=".." for installkernel writes
	#### "DONT:" Disable sandbox, that is a sandbox violation
	#### "export SANDBOX_ON=0"

        ## "DONT:" run these past this point, it was post ran in "src_prepare" and erases the compile made incuding vmlinux.
        ## make distclean
        ## make mrproper
        ## make clean

	## so far everthing has been made in "${S}" and would have to think on if there is a batter way to set all this up more orginized
	## There is still loose ends that need put in place that where causing fault
	## "${D}" is the image directory and is where the mirror for the file system is built
	## "${EROOT}" is where ever portage is cd'ed to and "${ROOT}" is a sandbox violation
	## Using "${EROOT}" past src_instal, is ="${ROOT}" thats also a sandbox violation
	## This is a custom kernel and proper note needs made as to where things are getting made so that the build will not be incomplete
        mkdir -p ${D}/boot/EFI/Liguros || die

        # Now to put the certificets in there new home
        mkdir -p ${CERTSDIR_NEW}
        rsync -ar ${S}/certs/ ${CERTSDIR_NEW} || die "cd failed 4"

	# if we didn't use genkernel, we're done. The kernel source tree is left in
	# an unconfigured state - you can't compile 3rd-party modules against it yet.
	make prepare || die
	make scripts || die

	local TARGETS=( modules_install )

        # ARM / ARM64 requires dtb
        if (use arm || use arm64); then
                TARGETS+=( dtbs_install )
        fi
        emake ${MAKECONF[@]} install INSTALL_PATH=${D}/boot/EFI

        if ${DO_I_HAVE_MODULES}; then
                emake ${MAKECONF[@]} ${TARGETS[@]} INSTALL_MOD_PATH=${D} INSTALL_PATH=${D}/boot/EFI/Liguros;
        fi

        ## This makes the /lib/modules/${KERNELTAGS}/build tree in ${D}
        installkernel ${KERNELTAGS} ${S}/arch/x86/boot/bzImage ${S}/System.map ${D}/boot/EFI/Liguros

        ## will need to mess with "installkernel" since did not put this in the right place
        cp ${S}/arch/x86/boot/bzImage ${D}/boot/EFI/

        ## This take the above tree and generate modules.dep and map files, in the ${KERNELTAGS} folder.
        if [[ -d ${USR_SRC_BUILD} ]]; then
                depmod -b ${D} -e -F System.map -a ${KERNELTAGS} || die
        fi
        if use sign-modules; then
            for x in $(find ${LIB_MODULES} -iname *.ko); do
                # ${CERTSDIR_NEW} defined previously in this function.
                ${S}/scripts/sign-file sha512 ${CERTSDIR}/signing_key.pem ${CERTSDIR}/signing_key.x509 $x || die
            done
        fi

        ## this all is setting stuff in place, "source" needs to be the source for initramfs
	rm -r ${LIB_MODULES}/source
	mkdir -p ${LIB_MODULES}/source
	rsync -ar ${WORKDIR}/${KERNELTAGS}/source/  ${LIB_MODULES}/source
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
        ${D}/boot/EFI/Liguros/initramfs-${KERNELTAGS}.img ${KERNELTAGS} || die ">>>Dracut: Building initramfs failed"
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
        if use symlink; then
                ln -sf ${D}/usr/src/linux-${KERNELTAG} ${D}/usr/src/linux
        fi

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
#       cd /kill/me || die "It stops"
}

pkg_postinst() {

   if use symlink; then
        # and now symlink the newly installed sources
	    ewarn ""
	    ewarn "WARNING... WARNING... WARNING"
	    ewarn ""
	    ewarn "/usr/src/linux symlink automatically set to linux-${KERNELTAG}"
	    ewarn ""
   fi

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
