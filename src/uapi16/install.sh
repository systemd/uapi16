#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Installs the C library of uapi16: the shared library with its links, the
# static library, uapi16.h and uapi16.pc. build.sh builds the two
# libraries.

set -eu

usage() {
	cat <<EOF
usage: $0 [--prefix=DIR] [--libdir=DIR] [--includedir=DIR]
       [--pkgconfigdir=DIR] [--builddir=DIR]

Installs libuapi16.so.VERSION with the links libuapi16.so.0 and
libuapi16.so, libuapi16.a, uapi16.h and uapi16.pc.

  --prefix=DIR        where to install [/usr/local]
  --libdir=DIR        the libraries [PREFIX/lib]
  --includedir=DIR    the header [PREFIX/include]
  --pkgconfigdir=DIR  uapi16.pc [LIBDIR/pkgconfig]
  --builddir=DIR      where build.sh put the two libraries
                      [\${CARGO_TARGET_DIR:-target}/release]

DESTDIR, if it is set, is put in front of every directory that is
installed to.
EOF
}

# CDPATH is where cd looks for a directory first, and it says where it went
# if it found it there. It has no say here.
here=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)

prefix=/usr/local
libdir=
includedir=
pkgconfigdir=
builddir=${CARGO_TARGET_DIR:-target}/release
for argument; do
	case $argument in
	--prefix=*) prefix=${argument#*=} ;;
	--libdir=*) libdir=${argument#*=} ;;
	--includedir=*) includedir=${argument#*=} ;;
	--pkgconfigdir=*) pkgconfigdir=${argument#*=} ;;
	--builddir=*) builddir=${argument#*=} ;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		exit 1
		;;
	esac
done
libdir=${libdir:-$prefix/lib}
includedir=${includedir:-$prefix/include}
pkgconfigdir=${pkgconfigdir:-$libdir/pkgconfig}
destdir=${DESTDIR:-}

fail() {
	echo "$0: $*" >&2
	exit 1
}

# A path as uapi16.pc has it: with a backslash before a space, which is how
# pkg-config reads a path with a space in it, and how meson writes one.
pc_path() {
	printf '%s\n' "$1" | sed 's/ /\\ /g'
}

shared=$builddir/libuapi16.so
static=$builddir/libuapi16.a
libs=$builddir/libuapi16.libs
for built in "$shared" "$static" "$libs"; do
	[ -f "$built" ] || fail "$built is missing, build.sh builds it"
done

# The version of the crate is the version of the file of the shared
# library and of uapi16.pc.
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$here/Cargo.toml" | head -n 1)
[ -n "$version" ] || fail "$here/Cargo.toml has no version"

# The name the shared library was linked with is the name of its first
# link. A shared library that cargo built has none, and no symbol versions
# either.
command -v readelf > /dev/null || fail "readelf is missing, which reads the name of $shared"
soname=$(readelf -d "$shared" | sed -n 's/.*(SONAME).*\[\(.*\)\]/\1/p')
[ -n "$soname" ] || fail "$shared has no SONAME: build.sh did not link it"

# What a program that links the static library links as well, as rustc
# listed it when it built the library.
static_libs=$(cat "$libs")

install -d "$destdir$libdir" "$destdir$includedir" "$destdir$pkgconfigdir"
install -m 0755 "$shared" "$destdir$libdir/libuapi16.so.$version"
ln -sf "libuapi16.so.$version" "$destdir$libdir/$soname"
ln -sf "libuapi16.so.$version" "$destdir$libdir/libuapi16.so"
install -m 0644 "$static" "$destdir$libdir/libuapi16.a"
install -m 0644 "$here/uapi16.h" "$destdir$includedir/uapi16.h"
cat > "$destdir$pkgconfigdir/uapi16.pc" <<EOF
# SPDX-License-Identifier: LGPL-2.1-or-later

prefix=$(pc_path "$prefix")
libdir=$(pc_path "$libdir")
includedir=$(pc_path "$includedir")

Name: uapi16
Description: Builds UAPI.16 file manifests of trees of files, and reads and writes them record by record
URL: https://github.com/systemd/uapi16
Version: $version
Cflags: -I\${includedir}
Libs: -L\${libdir} -luapi16
Libs.private: $static_libs
EOF
chmod 0644 "$destdir$pkgconfigdir/uapi16.pc"
