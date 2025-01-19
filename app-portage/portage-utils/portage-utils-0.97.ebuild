# Copyright 2021-2024 Liguros Authors
# Distributed under the terms of the GNU General Public License v2
EAPI=8

inherit flag-o-matic toolchain-funcs

DESCRIPTION="Small and fast Portage helper tools written in C"
HOMEPAGE="https://wiki.gentoo.org/wiki/Portage-utils"

LICENSE="GPL-2"
SLOT="0"
IUSE="openmp +qmanifest +qtegrity libressl static"
SRC_URI="https://dev.gentoo.org/~grobian/distfiles/${P}.tar.xz"
KEYWORDS="~alpha ~amd64 ~arm ~arm64 ~hppa ~ia64 ~m68k ~mips ~ppc ~ppc64 ~riscv ~s390 ~sparc ~x86 ~x64-cygwin ~amd64-linux ~x86-linux ~ppc-macos ~x64-macos ~sparc-solaris ~sparc64-solaris ~x64-solaris ~x86-solaris"

RDEPEND="
	qmanifest? (
		static? (
			app-crypt/gpgme:=[static-libs]
			app-crypt/libb2:=[static-libs]
		        !libressl? ( dev-libs/openssl:=[static-libs] )
	                libressl? ( >dev-libs/libressl-3.9.1:=[static-libs] )
			sys-libs/zlib:=[static-libs]
		)
		!static? (
			app-crypt/gpgme:=
			app-crypt/libb2:=
	                !libressl? ( dev-libs/openssl:= )
	                libressl? ( >dev-libs/libressl-3.9.1:= )
			sys-libs/zlib:=
		)
	)
	qtegrity? (
		static? (
	                !libressl? ( dev-libs/openssl:=[static-libs] )
	                libressl? ( >dev-libs/libressl-3.9.1:=[static-libs] )
		)
		!static? (
	                !libressl? ( dev-libs/openssl:= )
	                libressl? ( >dev-libs/libressl-3.9.1:= )
		)
	)
"
DEPEND="${RDEPEND}"
BDEPEND="virtual/pkgconfig"

src_configure() {
	use static && append-ldflags -static

	econf \
		--disable-maintainer-mode \
		--with-eprefix="${EPREFIX}" \
		$(use_enable qmanifest) \
		$(use_enable qtegrity) \
		$(use_enable openmp)
}
