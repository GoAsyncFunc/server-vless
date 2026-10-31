#!/bin/sh
# Downloads the geo data files Xray loads while building a node config and
# verifies each against a pinned sha256.
#
# Xray resolves the direct egress's "geoip:private" rule by opening geoip.dat,
# so the file is a hard runtime requirement and every artifact we publish has to
# carry it. geosite.dat is only read when a route or the panel DNS names a
# "geosite:" attribute, but it ships alongside so operators do not have to fetch
# it separately the first time they use one.
#
# Both the release archives and the Docker image call this script, so the rule
# set cannot drift between the two. The tag and hashes are pinned to make the
# output reproducible; bump all three together after verifying a new release.
#
# Deliberately not read from the environment. A caller that can set all three
# can point the download at a different release and supply that release's real
# checksums, which turns the verification into a self-certifying no-op. Change
# them here, in a reviewed commit, instead.
#
# Usage: fetch-geo-assets.sh [DEST_DIR]
set -eu

GEO_TAG="202609240010"
GEOIP_SHA256="f3370cf391831bb01e1e662df88596164d136e7d9f81a91c00bae26587e02d72"
GEOSITE_SHA256="224798ccfaf4fb09be31b63c0807b2969641a74350902c76926a6c0e9d3347ba"

DEST="${1:-.}"
BASE_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${GEO_TAG}"
ATTEMPTS=3

mkdir -p "${DEST}"
# A download that fails or does not verify must not leave a half-written or
# wrong file where the build would pick it up: every file lands in a .part
# first and is only moved into place once its checksum matched.
trap 'rm -f "${DEST}"/*.part' EXIT

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		echo "neither sha256sum nor shasum is available to verify ${1}" >&2
		return 1
	fi
}

download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout 15 --max-time 300 -o "$2" "$1"
	else
		wget -q -T 60 -O "$2" "$1"
	fi
}

fetch() {
	name="$1"
	want="$2"
	url="${BASE_URL}/${name}"
	part="${DEST}/${name}.part"

	# GitHub release downloads fail transiently often enough that one attempt
	# makes the build flaky; three with a short pause is enough for that
	# without hiding an outage.
	attempt=1
	until download "${url}" "${part}"; do
		rm -f "${part}"
		if [ "${attempt}" -ge "${ATTEMPTS}" ]; then
			echo "${name}: download failed after ${ATTEMPTS} attempts" >&2
			exit 1
		fi
		attempt=$((attempt + 1))
		echo "${name}: download failed, retrying (${attempt}/${ATTEMPTS})" >&2
		sleep 2
	done

	got="$(sha256_of "${part}")"
	if [ "${got}" != "${want}" ]; then
		rm -f "${part}"
		echo "${name}: sha256 mismatch, got ${got}, want ${want}" >&2
		exit 1
	fi
	mv -f "${part}" "${DEST}/${name}"
	echo "${name}: ${GEO_TAG} sha256 ${got} ok"
}

fetch geoip.dat "${GEOIP_SHA256}"
fetch geosite.dat "${GEOSITE_SHA256}"
