#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Builds the C library of uapi16: the static library with cargo, and the
# shared library from the static one with the C compiler. install.sh
# installs the two.
#
# The shared library is linked the way a C library is: by the C compiler,
# with CFLAGS and LDFLAGS, and with the version script libuapi16.sym, which
# says what it exports. cargo could build a shared library itself, but
# rustc gives the linker a version script of its own for one, and no symbol
# gets a version next to that.

set -eu

usage() {
	cat <<EOF
usage: $0 [--builddir=DIR] [--keep-debug] [-- CARGO-OPTION...]

Builds libuapi16.a with cargo and links libuapi16.so from it.

  --builddir=DIR  where cargo puts what it builds [release in the
                  target directory of cargo, which cargo names]
  --keep-debug    keep the debug sections of the static library in the
                  shared one, for a build that takes them out later
  CARGO-OPTION    an option for cargo rustc, such as --locked. For
                  --target, name the directory of that target with
                  --builddir.

cargo builds for another target in a directory of that target, also
where CARGO_BUILD_TARGET or its configuration names the target. This
fails unless --builddir names the directory cargo put the library into.

CC is the C compiler that links the shared library [cc]. CFLAGS and
LDFLAGS are what it is given besides, in that order.
EOF
}

# CDPATH is where cd looks for a directory first, and it says where it went
# if it found it there. It has no say here.
here=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)

builddir=
strip_debug=-Wl,--strip-debug
while [ $# -gt 0 ]; do
	case $1 in
	--builddir=*) builddir=${1#*=} ;;
	--keep-debug) strip_debug= ;;
	--)
		shift
		break
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		exit 1
		;;
	esac
	shift
done

fail() {
	echo "$0: $*" >&2
	exit 1
}

# What cargo builds for another target is not where it puts what it builds
# for the host.
for option; do
	case $option in
	--target | --target=*) [ -n "$builddir" ] || fail "--target needs --builddir" ;;
	esac
done

# Where cargo builds, which it says itself: target at the top of the
# workspace unless CARGO_TARGET_DIR or its configuration name another
# directory, whatever directory this is run from. What it builds for the
# host is in release below it. What it builds for another target is in a
# directory of that target, also where no option names the target but
# CARGO_BUILD_TARGET or the configuration of cargo. Nothing says that
# before cargo has built the library, so where it put it is checked below.
if [ -z "$builddir" ]; then
	target=$(cargo metadata --manifest-path "$here/Cargo.toml" --format-version 1 --no-deps |
		sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
	# A backslash is how cargo writes a character that this does not read.
	case $target in
	'' | *\\*) fail "cargo does not say where it builds, say it with --builddir" ;;
	esac
	builddir=$target/release
fi
mkdir -p "$builddir"
builddir=$(CDPATH= cd -P -- "$builddir" && pwd)
static=$builddir/libuapi16.a
shared=$builddir/libuapi16.so
libs=$builddir/libuapi16.libs

# The static library. rustc writes what a program that links it has to link
# as well into a file, which install.sh puts into uapi16.pc. It writes the
# file when it builds the library, and into a file of another name first:
# the library it builds need not be the one in $builddir. One that an
# earlier run left there is of no use.
#
# cargo says what it built in messages of one line of JSON each, also for
# what it had built before and does not build again, and shows what the
# compiler says as it does without them.
rm -f "$libs.new"
messages=$(cargo rustc --manifest-path "$here/Cargo.toml" --release --features capi --crate-type staticlib \
	--message-format=json-render-diagnostics "$@" -- --print "native-static-libs=$libs.new")

# The message for the static library names the file it is in. A backslash
# is how cargo writes a character that this does not read, and more than
# one line is more than one library.
built=$(printf '%s\n' "$messages" |
	sed -n '/"reason":"compiler-artifact"/s/.*"filenames":\[[^]]*"\([^"]*\/libuapi16\.a\)".*/\1/p')
case $built in
'' | *\\* | *'
'*)
	rm -f "$libs.new"
	fail "cargo does not say where it put libuapi16.a"
	;;
esac

# A library that is in $builddir from an earlier build is not what cargo
# built now if cargo built for another target. What that build left in
# $builddir stays as it is then.
built=$(CDPATH= cd -P -- "$(dirname -- "$built")" && pwd)/libuapi16.a
if [ "$built" != "$static" ]; then
	rm -f "$libs.new"
	fail "cargo built $built and not $static, name its directory with --builddir"
fi

# cargo does not build a library again that it has, also not where the file
# rustc wrote with it is gone, so nothing writes that file again then.
[ ! -f "$libs.new" ] || mv -f "$libs.new" "$libs"
[ -f "$libs" ] || fail "$libs is missing, and rustc only writes it when cargo builds" \
	"libuapi16.a, which cargo did not do again. Run 'cargo clean --manifest-path" \
	"$here/Cargo.toml --release -p uapi16', with the --target of this build if it has" \
	"one, and then this again"

# The shared library is all of the static one. libuapi16.sym exports the
# functions of uapi16.h from it and nothing else, and a name in it that the
# library does not define fails the link. The other options are those rustc
# gives the linker for a shared library of its own: what the functions do
# not need is left out, only the libraries that are needed are recorded,
# the library is bound when it is loaded and read-only after that, its
# stack is not executable and it has no debug sections. CFLAGS and then
# LDFLAGS come after all of that, so they can say otherwise. A link gets
# both from automake and from meson as well.
#
# $CC, $CFLAGS, $LDFLAGS and what is in $libs are lists of words.
# shellcheck disable=SC2086
${CC:-cc} -shared -o "$shared" \
	-Wl,-soname,libuapi16.so.0 \
	-Xlinker "--version-script=$here/libuapi16.sym" -Wl,--no-undefined-version \
	-Wl,--gc-sections -Wl,--as-needed \
	-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack $strip_debug \
	${CFLAGS:-} ${LDFLAGS:-} \
	-Wl,--whole-archive "$static" -Wl,--no-whole-archive \
	$(cat "$libs")

echo "built $static and $shared"
