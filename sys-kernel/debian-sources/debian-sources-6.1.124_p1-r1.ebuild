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

IUSE="binary clang custom-cflags debug dtrace ec2 efi grub +hardened lvm libressl mcelog makeconfig +microcode multipath nvidia rEFInd +savedconfig openssl secureboot symlink systemd wireguard xen tree"

REQUIRED_USE="hardened symlink"

BDEPEND="
	sys-devel/bc
	debug? ( dev-util/dwarves )
	virtual/libelf
"

DEPEND="
	binary? (
                sys-kernel/dracut
                sys-kernel/installkernel[dracut]
		dev-util/pahole
		sys-fs/squashfs-tools
		lvm? ( sys-kernel/genkernel
		       sys-fs/lvm2[lvm,-thin] )
		)
	dtrace? (
		dev-util/dtrace-utils
		dev-libs/libdtrace-ctf
	)
	efi? ( sys-boot/efibootmgr )
	multipath? (
		sys-fs/multipath-tools
	)
	openssl? ( dev-libs/openssl )
	systemd? ( sys-apps/systemd )
	!systemd? ( virtual/udev )
	secureboot? ( sys-firmware/edk2-bin[secureboot]
		|| ( dev-libs/openssl
		     dev-libs/libressl
        )
		sys-apps/kmod
	)
"

RDEPEND="
	sys-apps/coreutils[xattr(-)]
	>=sys-apps/kmod-23[tools,pkcs7]
	>=sys-apps/util-linux-2.21
	virtual/pkgconfig[native-symlinks(+)]
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

#########################################
# modules installkernel can run live here
# @=/usr/lib/kernel/install.d/
#############################

# both gentoo and liguros want this as the name
KERNELTAGS="${DEB_PV_BASE}-hardened1"

KERNELTAG="${DEB_PV_BASE}${MODULE_EXT}"
D_FILESDIR="${D}/var/db/repos/liguros-xxx/sys-kernel/debian-sources/files"
PORTAGE_BUILDDIR="/var/tmp/portage/sys-kernel/debian-sources-6.1.124_p1-r1"
USR_SRC_BUILD="${D}/lib/modules/${KERNELTAGS}/build"
CERTSDIR_NEW="${D}/etc/kernel/certs/${KERNELTAGS}"
LIB_MODULES="${D}/lib/modules/${KERNELTAGS}"
GRAPHENE_LIST="${S}/${SLOT}/GRAPHENE_LIST"
DEBIAN_LIST="${S}/${SLOT}/DEBIAN_LIST"
GENTOO_LIST="${S}/${SLOT}/GENTOO_LIST"
DTRACE_LIST="${S}/${SLOT}/DTRACE_LIST"

# cairfull using these, becuase can cause a sandbox violation
SAVEDCONFIG="/etc/portage/savedconfig/${CATEGORY}/${PN}"
CERTSDIR="/etc/kernel/certs/${MODULE_EXT}"
CLEAN_USR="/usr/src/linux-${KERNELTAGS}"

# do not rsync to this location, it will brake the symlink and use /lib64 instead
# portage makes the modules in /lib and why it is used but be carfull with it
CLEAN_LIB="/lib/modules/${KERNELTAGS}"

# TODO: manage HARDENED_PATCHES and GENTOO_PATCHES can be managed in a git repository and packed into tar balls per version.

pkg_pretend() {
	# Ensure we have enough disk space to compile
	if use binary ; then
		###########################
		# installkernel can do this
		# ${@}=85-check-diskspace.install
		################################
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
   if use binary; then
        # unpack the kernel sources
	unpack ${KERNEL} || die "failed to unpack kernel sources"

	# unpack the kernel patches
        unpack ${DEB_PATCH} || die "failed to unpack debian patches"

	# Patches to graphene source
	rsync -a ${FILESDIR}/${SLOT}/ ${SLOT} || die "failed to copy patch"
   fi
}

src_prepare() {
   if use binary; then
        ENV_SETUP_MAKECONF
	debug-print-function ${FUNCNAME} ${@}

	mkdir -p ${WORKDIR}/${KERNELTAGS}/source || die
	rsync -ar ${S}/ ${WORKDIR}/${KERNELTAGS}/source || die

	### PATCHES ###

        ## copy the debian patches into the kernel sources work directory (config-extract and graphene patches requires this).
        ## there is no need to punt the debian uefi certification and I put it where needs to be for future copy

	rsync -ar ${WORKDIR}/debian/ ${S}/debian
	rsync -ar ${WORKDIR}/${SLOT}/ ${S}/${SLOT}
	rsync -ar ${S}/debian/certs ${S}/certs || die "cd failed 3"

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
	sed -i -e 's:#export\tINSTALL_PATH:export\tINSTALL_PATH:' Makefile || die "failed to fix-up INSTALL_PATH in kernel Makefile"

	### GENERATE CONFIG ###

	# Copy 'config-extract' tool to the work directory
	rsync -ar ${FILESDIR}/config-extract-6.1/ ./config-extract || die

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

		if use secureboot; then
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
		fi
        # See above comment re: LibreSSL
	        if use libressl; then
			echo "CONFIG_MODULE_SIG_SHA1=y" >> .config
		        else
			echo "CONFIG_MODULE_SIG_SHA512=y" >> .config
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

	#${@}=35-amd-microcode-systemd.install
	#${@}=35-intel-microcode-systemd.install
}

src_test() {
	addwrite /dev/kvm
}

src_configure() {
        unset KBUILD_OUTPUT
   if use binary ; then
        ENV_SETUP_MAKECONF
        if use savedconfig; then
	echo "############################################################################################################"
	echo "# You need .config in /etc/portage/savedconfig/sys-kernel/debian-sources/ for the savedconfig flag to work #"
	echo "#             Using the tree flag with USE '-binary', will put one in place for you			 #"
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
   if use binary; then
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
   if use tree; then
	rsync -ar ${S}/${SLOT}/tree/ ${D}
   fi
   if use binary; then
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
        emake ${MAKECONF[@]} install INSTALL_PATH=${D}/boot/EFI/Liguros

        if ${DO_I_HAVE_MODULES}; then
                emake ${MAKECONF[@]} ${TARGETS[@]} INSTALL_MOD_PATH=${D} INSTALL_PATH=${D}/boot/EFI/Liguros;
        fi

        ## This makes the /lib/modules/${KERNELTAGS}/build tree in ${D}
        installkernel ${KERNELTAGS} ${S}/arch/x86/boot/bzImage ${S}/System.map ${D}/boot/EFI/Liguros

        ## will need to mess with "installkernel" since did not put this in the right place
        cp ${S}/arch/x86/boot/bzImage ${D}/boot/EFI/Liguros

	if use secureboot; then
		sbsing --key /root/secureboot/MOK.key --cert /root/secureboot/MOK.crt /boot/vmlinuz-${KERNELTAGS}
	fi

        ## This take the above tree and generate modules.dep and map files, in the ${KERNELTAGS} folder.
	if use nvidia; then
		rsync -ar ${CLEAN_LIB}/video/ ${LIB_MODULES}/video
	fi
        if [[ -d ${USR_SRC_BUILD} ]]; then
                depmod -b ${D} -ae -F System.map ${KERNELTAGS} || die
        fi

	### This all is redundent to be put in this ebuild, modules like nvidia-drivers do this on there own
	# if use sign-modules; then
	# for x in $(find ${LIB_MODULES} -iname *.ko); do
	# #CERTSDIR_NEW} defined previously in this function.
	# ${S}/scripts/sign-file sha512 ${CERTSDIR_NEW}/signing_key.pem ${CERTSDIR_NEW}/signing_key.x509 $x || die
	# done
	# fi

        ## this all is setting stuff in place, "source" needs to be the source for initramfs
	rm -r ${LIB_MODULES}/source
	mkdir -p ${LIB_MODULES}/{build,source}
	mkdir -p ${D}/usr/src
	rsync -ar ${WORKDIR}/${KERNELTAGS}/source/  ${LIB_MODULES}/source
	rsync -ar ${S}/ ${D}/usr/src/linux-${KERNELTAGS}
	cd ${D}

	dosym .${CLEAN_USR}/ ${CLEAN_LIB}/build || die

	if use symlink; then
		dosym ./linux-${KERNELTAGS}  /usr/src/linux
	fi
   fi

   if use tree; then
        rsync -ar ${FILESDIR}/tree/ ${D}
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

   if use symlink; then
        # and now symlink the newly installed sources
	    ewarn ""
	    ewarn "WARNING... WARNING... WARNING"
	    ewarn ""
	    ewarn "/usr/src/linux symlink automatically set to linux-${KERNELTAG}"
	    ewarn ""
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

   if use grub; then
        ewarn ""
   fi
   if use rEFInd; then
        ewarn ""
   fi

   if use binary; then
	if [[ -e /etc/boot.conf ]]; then
		ego boot update
	fi
   fi
#	cd /kill/me || die
}
