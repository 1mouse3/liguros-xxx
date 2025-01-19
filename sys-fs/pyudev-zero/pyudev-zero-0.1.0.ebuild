# Copyright 2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

DISTUTILS_USE_PEP517=setuptools
PYTHON_COMPAT=( python3_{10..12} )

inherit distutils-r1

DESCRIPTION="Drop-in replacement for libudev intended to work with any device manager"
HOMEPAGE="https://github.com/mo10/pyudev-zero"
SRC_URI="https://github.com/mo10/pyudev-zero/archive/refs/tags/v0.1.0.tar.gz -> ${P}.tar.gz"

LICENSE="ISC"
SLOT="0"
KEYWORDS="alpha amd64 arm arm64 hppa ia64 loong m68k mips ppc ppc64 riscv s390 sparc x86"

DEPEND=" !sys-apps/systemd-utils[udev] !sys-fs/eudev !sys-fs/udev "
RDEPEND="${DEPEND}"
#BDEPEND="setuptools"
BDEPEND="
    dev-python/cython[${PYTHON_USEDEP}]
"
python_prepare_all() {
	distutils-r1_python_prepare_all

	sed "/readme.md/d" -i pyproject.toml || die
}

python_install_all () {
	distutils-r1_python_install_all
}

#pkg_postinst() {


#	mv /var/tmp/portage/sys-fs/pyudev-zero-0.1.0/image/usr/lib64 /usr/lib64

