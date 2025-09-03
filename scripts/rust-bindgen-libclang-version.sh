#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Print the version of `libclang` used by the Rust bindings generator in a 5 or 6-digit form,
# and a non-canonical form if `--with-non-canonical` option is specified.
# Also, perform the minimum version check.

set -e

# If the script fails, print 0 to stdout as the version output.
trap 'if [ $? -ne 0 ]; then echo 0; fi' EXIT

while [ $# -gt 0 ]; do
	case "$1" in
	--with-non-canonical)
		with_non_canonical=1
		;;
	-*)
		echo >&2 "Unknown option: $1"
		exit 1
		;;
	*)
		break
		;;
	esac
	shift
done

get_bindgen_libclang_version()
{
	# Invoke `bindgen` to get the `libclang` version found by `bindgen`. This step
	# may already fail if, for instance, `libclang` is not found, thus inform the
	# user in such a case.
	output=$( \
		LC_ALL=C "$@" $(dirname $0)/rust-bindgen-libclang-version.h 2>&1 >/dev/null
	) || code=$?
	if [ -n "$code" ]; then
		echo >&2 "***"
		echo >&2 "*** Running '$@' to check the libclang version (used by the Rust"
		echo >&2 "*** bindings generator) failed with code $code. This may be caused by"
		echo >&2 "*** a failure to locate libclang. See output and docs below for details:"
		echo >&2 "***"
		echo >&2 "$output"
		echo >&2 "***"
		exit 1
	fi

	# Unlike other version checks, note that this one does not necessarily appear
	# in the first line of the output, thus no `sed` address is provided.
	version=$( \
		echo "$output" \
			| sed -nE 's:.*clang version ([0-9]+\.[0-9]+\.[0-9]+).*:\1:p'
	)
	if [ -z "$version" ]; then
		echo >&2 "***"
		echo >&2 "*** Running '$@' to check the libclang version (used by the Rust"
		echo >&2 "*** bindings generator) did not return an expected output. See output"
		echo >&2 "*** and docs below for details:"
		echo >&2 "***"
		echo >&2 "$output"
		echo >&2 "***"
		exit 1
	fi
	echo "$version"
}

# Convert the version string x.y.z to a canonical 5 or 6-digit form.
get_canonical_version()
{
	IFS=.
	set -- $1
	echo $((10000 * $1 + 100 * $2 + $3))
}

min_tool_version=$(dirname $0)/min-tool-version.sh

version=$(get_bindgen_libclang_version "$@")
min_version=$($min_tool_version llvm)
cversion=$(get_canonical_version $version)
min_cversion=$(get_canonical_version $min_version)

if [ "$cversion" -lt "$min_cversion" ]; then
	echo >&2 "***"
	echo >&2 "*** libclang (used by the Rust bindings generator '$@') is too old."
	echo >&2 "***   Your version:    $version"
	echo >&2 "***   Minimum version: $min_version"
	echo >&2 "***"
	exit 1
fi

echo "$cversion"
if [ -n "$with_non_canonical" ]; then
	echo "$version"
fi
