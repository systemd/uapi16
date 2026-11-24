#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Tests the C library of uapi16 as install.sh installed it:
#
#     ./build.sh
#     ./install.sh --prefix=DIR
#     tests/capi.sh DIR [COMMAND...]
#
# It checks what the shared library exports, builds tests/capi.c against
# the installed header, once with the shared and once with the static
# library, and runs both. Then it builds the programs of examples/ against
# the shared library, runs each on files it makes, and checks what they
# did. It takes the flags for that from uapi16.pc.
#
# The tests and the examples run under COMMAND if one is given, such as
# valgrind. CC is the compiler, and CFLAGS are its flags: unless they are
# set, the tests and the examples are built with the address and the
# undefined behavior sanitizer. LIBDIR is where the libraries are, if that
# is not DIR/lib.

set -eu

[ $# -ge 1 ] || {
	echo "usage: $0 DIR [COMMAND...]" >&2
	exit 1
}
prefix=$1
shift
libdir=${LIBDIR:-$prefix/lib}
# CDPATH is where cd looks for a directory first, and it says where it went
# if it found it there. It has no say here.
here=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)
cc=${CC:-cc}
cflags=${CFLAGS:--std=c11 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined}
warnings="-Wall -Wextra -Werror"

fail() {
	echo "$0: $*" >&2
	exit 1
}

export PKG_CONFIG_PATH="$libdir/pkgconfig"
includes=$(pkg-config --cflags uapi16)
shared_libs=$(pkg-config --libs uapi16)
# The same with what the static library needs, and with the static library
# named, since a linker that finds both takes the shared one.
static_libs=$(pkg-config --static --libs uapi16 | sed 's/-luapi16/-l:libuapi16.a/')
# uapi16.pc has a backslash before a space in a path, see install.sh.
includedir=$(pkg-config --variable=includedir uapi16 | sed 's/\\ / /g')

# The shared library exports the functions uapi16.h declares, each at the
# node of the release that added it, and nothing else. So far that is
# LIBUAPI16_0.1.0 for every function. A node never changes once it is
# released, so a release that adds functions adds its node here. GNU ld
# also lists each version node as an absolute symbol of its name, which is
# no export. lld lists none.
shared=$libdir/libuapi16.so.0
[ -e "$shared" ] || fail "$shared is missing"
declared=$(sed -n '/^static /d; s/^[a-z][^(]*[ *]\(uapi16_[a-z0-9_]*\)(.*/\1/p' "$includedir/uapi16.h" |
	sort)
exported=$(nm -D --defined-only --with-symbol-versions "$shared" |
	sed '/ A LIBUAPI16_[0-9.]*$/d; s/^.* //' | sort)
[ -n "$declared" ] || fail "$includedir/uapi16.h declares no functions"
elsewhere=$(echo "$exported" | grep -v '@@LIBUAPI16_0\.1\.0$' || true)
[ -z "$elsewhere" ] || fail "$shared does not export at LIBUAPI16_0.1.0:" $elsewhere
[ "$(echo "$exported" | sed 's/@@.*//')" = "$declared" ] ||
	fail "$shared does not export what uapi16.h declares:" $exported
echo "ok symbols ($(echo "$declared" | wc -l))"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The trees of the tests have a hard link. Where the temporary directory
# can hold none, as on FAT, nothing more is tested.
: > "$work/linked"
if ! ln "$work/linked" "$work/linked-too" 2> /dev/null; then
	echo "skipping the tests and the examples: $work can hold no hard link" >&2
	exit 0
fi
rm "$work/linked" "$work/linked-too"

# $cc, $cflags and $warnings are lists of words. What pkg-config said is
# written for a shell to read, with a backslash before a space in a path,
# so the shell reads it once more here.
#
# The test holds a call of the library in its malloc(), see capi.c. With
# --wrap=malloc the linker gives everything it links into the program the
# malloc() of the test: the test itself and the static library. The shared
# library keeps the one of the C library.
wrap="-Wl,--wrap=malloc"
eval "\$cc \$cflags \$warnings -pthread $includes -o \"\$work/capi-shared\" \"\$here/capi.c\" \
	\$wrap $shared_libs -Xlinker -rpath -Xlinker \"\$libdir\""
eval "\$cc \$cflags \$warnings -pthread $includes -o \"\$work/capi-static\" \"\$here/capi.c\" \
	\$wrap $static_libs"

# Each test is linked with the library it is for.
needed() {
	readelf -d "$1" | grep -c 'NEEDED.*libuapi16' || true
}
[ "$(needed "$work/capi-shared")" = 1 ] || fail "capi-shared is not linked with the shared library"
[ "$(needed "$work/capi-static")" = 0 ] || fail "capi-static is linked with the shared library"

for library in shared static; do
	echo "# the $library library"
	"$@" "$work/capi-$library"
done

# The programs of examples/, built as tests/capi.c is, with the shared
# library. Each runs under COMMAND on files that are made below $work, and
# what it printed and wrote is checked. assemble takes what build made, so
# build comes first.
examples="generate listing build assemble sorted signed"

# Fails unless the file $1 has the lines $2, $3 and so on.
has_lines() {
	file=$1
	shift
	[ "$(cat "$file")" = "$(printf '%s\n' "$@")" ] || fail "$file has:" "$(cat "$file")"
}

# Fails unless the manifest $1 lists the file objects $2, $3 and so on, in
# that order. Each record is a line, and that of a file object has its
# name. The root has none.
lists() {
	manifest=$1
	shift
	names=$(sed -n 's/^.*"name":"\([^"]*\)".*$/\1/p' "$manifest")
	[ "$names" = "$(printf '%s\n' "$@")" ] || fail "$manifest lists:" $names
}

# A line for every file below the directory $1, in the order of their
# names: its name and its type, the target of a symbolic link, and the
# number of names and the hash of the data of a regular file.
files() {
	(
		CDPATH= cd -- "$1"
		find . ! -name . | LC_ALL=C sort | while IFS= read -r name; do
			if [ -L "$name" ]; then
				echo "$name link to $(readlink "$name")"
			elif [ -f "$name" ]; then
				echo "$name file $(stat -c %h "$name") $(sha256sum < "$name" | cut -d ' ' -f 1)"
			else
				echo "$name $(stat -c %F "$name")"
			fi
		done
	)
}

# A line for every regular file below the directory $1, in the order of
# their names: its name, its access mode and its modification time.
attributes() {
	(CDPATH= cd -- "$1" && find . -type f -exec stat -c '%n %a %y' {} + | LC_ALL=C sort)
}

# Makes the directory $1 with a tree in it: directories, one of them
# empty, regular files with data and without, one with holes and one with
# two names, and a symbolic link. Some of the regular files have modes and
# modification times of their own. A manifest lists a/x before a-b, which
# strcmp() does not.
make_tree() {
	mkdir "$1" "$1/a" "$1/sub" "$1/sub/deeper"
	echo x > "$1/a/x"
	echo a-b > "$1/a-b"
	: > "$1/empty"
	# 1 MiB, with data at 512 KiB and holes before and after it.
	truncate -s 1M "$1/hole"
	echo hole | dd of="$1/hole" bs=4096 seek=128 conv=notrunc status=none
	echo one > "$1/one"
	ln "$1/one" "$1/sub/two"
	ln -s a/x "$1/link"
	chmod 0640 "$1/a/x"
	chmod 0755 "$1/a-b"
	touch -d 2001-02-03T04:05:06.123456789Z "$1/a/x"
	touch -d 2002-03-04T05:06:07.987654321Z "$1/one"
}

# generate writes the manifest of a tree to a new file, and says what it
# lists. It leaves out a file whose name a manifest can't hold, and it
# replaces no file.
check_generate() {
	make_tree "$work/generate-tree"
	mkfifo "$work/generate-tree/fifo"
	: > "$work/generate-tree/$(printf 'not\377utf-8')"
	"$@" "$work/generate" "$work/generate-tree" "$work" generate.manifest > "$work/generate.out" \
		2> "$work/generate.err" || fail "generate exited with $?:" "$(cat "$work/generate.err")"
	has_lines "$work/generate.out" "6 files, 4 directories, 2 others, 1048590 bytes"
	has_lines "$work/generate.err" "1 files have names a manifest can't hold and were left out"
	lists "$work/generate.manifest" a a/x a-b empty fifo hole link one sub sub/deeper sub/two
	rc=0
	"$@" "$work/generate" "$work/generate-tree" "$work" generate.manifest 2> "$work/generate.err" || rc=$?
	[ "$rc" = 1 ] || fail "generate exited with $rc for a name that is taken"
	has_lines "$work/generate.err" "generate.manifest: there is a file of that name already"
}

# listing writes the manifest of the records it has. The two names of tool
# are one file and have one token, and its data, hello, is in the store
# under the name of its hash.
check_listing() {
	"$@" "$work/listing" "$work" listing.manifest > "$work/listing.out" || fail "listing exited with $?"
	has_lines "$work/listing.out" "7 records"
	lists "$work/listing.manifest" usr usr/bin usr/bin/alias usr/bin/tool usr/libexec usr/libexec/tool
	blob=blobs/$(printf hello | sha256sum | cut -d ' ' -f 1)
	for name in usr/bin/tool usr/libexec/tool; do
		record=$(grep -F "\"name\":\"$name\"" "$work/listing.manifest")
		case $record in
		*"\"contents\":[{\"file\":\"$blob\"}]"*) ;;
		*) fail "$name does not have its data in $blob:" "$record" ;;
		esac
		case $record in
		*'"inodeToken":1,'*) ;;
		*) fail "$name does not have the token 1:" "$record" ;;
		esac
	done
}

# build copies a tree into a new directory, with the data, the names and
# the links of its files, and writes the manifest of what it copied. Its
# root has the identity build gives the file system.
check_build() {
	"$@" "$work/build" "$work/tree" "$work/build-image" > "$work/build.manifest" || fail "build exited with $?"
	[ "$(files "$work/build-image")" = "$(files "$work/tree")" ] || fail "build-image is not a copy of tree"
	lists "$work/build.manifest" a a/x a-b empty hole link one sub sub/deeper sub/two
	root=$(head -n 1 "$work/build.manifest")
	case $root in
	*'"fsLabel":"example"'*) ;;
	*) fail "the root does not have the label of build:" "$root" ;;
	esac
	case $root in
	*'"fsUUID":"6f1d0a42-9c1e-4b7a-8d33-520c7e11a905"'*) ;;
	*) fail "the root does not have the UUID of build:" "$root" ;;
	esac
}

# assemble makes the tree again from the manifest of build and the files
# build copied: the data, the names and the links of its files, and the
# access modes and the modification times of its regular files.
check_assemble() {
	"$@" "$work/assemble" "$work/build-image" "$work/assemble-image" < "$work/build.manifest" ||
		fail "assemble exited with $?"
	[ "$(files "$work/assemble-image")" = "$(files "$work/tree")" ] || fail "assemble-image is not tree"
	[ "$(attributes "$work/assemble-image")" = "$(attributes "$work/tree")" ] ||
		fail "the regular files of assemble-image do not have the modes and the times of tree"
}

# sorted writes the records of the directories and the regular files of a
# tree as its walk comes to them, which is the order of the manifest.
check_sorted() {
	"$@" "$work/sorted" "$work/tree" > "$work/sorted.manifest" || fail "sorted exited with $?"
	lists "$work/sorted.manifest" a a/x a-b empty hole one sub sub/deeper sub/two
}

# signed writes a manifest with a signature object, and reads it back with
# what the signature signs.
check_signed() {
	"$@" "$work/signed" "$work/signed.manifest" > "$work/signed.out" || fail "signed exited with $?"
	has_lines "$work/signed.out" hello.txt "a signature by openpgp: good"
}

echo "# the examples"
make_tree "$work/tree"
for example in $examples; do
	eval "\$cc \$cflags \$warnings $includes -o \"\$work/\$example\" \"\$here/../examples/\$example.c\" \
		$shared_libs -Xlinker -rpath -Xlinker \"\$libdir\""
	"check_$example" "$@"
	echo "ok example $example"
done
