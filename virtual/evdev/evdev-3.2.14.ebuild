# Copyright 1999-2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8


DESCRIPTION="Virtual to select between different libudev daemon providers"

SLOT="0/1"
KEYWORDS="~alpha amd64 arm arm64 hppa ~ia64 ~loong ~m68k ~mips ppc ppc64 ~riscv ~s390 sparc x86"
IUSE="systemd"

DEPEND=" !sys-apps/systemd-utils[udev] !sys-fs/eudev !sys-fs/udev !sys-apps/systemd "
RDEPEND="
	!systemd? ( || (
                sys-libs/libudev-zero
                dev-python/pyudev
        ) )
"
