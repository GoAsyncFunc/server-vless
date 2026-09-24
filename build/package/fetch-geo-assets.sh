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
# Usage: fetch-geo-assets.sh [DEST_DIR]
set -eu

GEO_TAG="${GEO_TAG:-202609240010}"
GEOIP_SHA256="${GEOIP_SHA256:-f3370cf391831bb01e1e662df88596164d136e7d9f81a91c00bae26587e02d72}"
GEOSITE_SHA256="${GEOSITE_SHA256:-224798ccfaf4fb09be31b63c0807b2969641a74350902c76926a6c0e9d3347ba}"

DEST="${1:-.}"
BASE_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${GEO_TAG}"

mkdir -p "${DEST}"

fetch() {
	name="$1"
	want="$2"
	url="${BASE_URL}/${name}"

	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "${DEST}/${name}" "${url}"
	else
		wget -q -O "${DEST}/${name}" "${url}"
	fi

	got="$(sha256sum "${DEST}/${name}" | awk '{print $1}')"
	if [ "${got}" != "${want}" ]; then
		echo "${name}: sha256 mismatch, got ${got}, want ${want}" >&2
		exit 1
	fi
	echo "${name}: ${GEO_TAG} sha256 ${got} ok"
}

fetch geoip.dat "${GEOIP_SHA256}"
fetch geosite.dat "${GEOSITE_SHA256}"
