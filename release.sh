#!/bin/sh
# Build the three release zips for the current version.
# Usage: ./release.sh [output directory]
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
version=$(sed -n "s/.*const VERSION = '\\([^']*\\)'.*/\\1/p" "$root/src/Version.php")
if [ -z "$version" ]; then
    echo 'Could not read the version from src/Version.php.' >&2
    exit 1
fi

out=${1:-"$root/dist"}
mkdir -p "$out"
out=$(CDPATH= cd -- "$out" && pwd)

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

full="$stage/last-words-$version"
mkdir -p "$full"
rsync -a \
    --exclude '.git/' \
    --exclude 'dist/' \
    --exclude 'data/' \
    --exclude 'data_path.php' \
    --exclude '*.sqlite' \
    --exclude '*.sqlite-wal' \
    --exclude '*.sqlite-shm' \
    --exclude '.DS_Store' \
    "$root/" "$full/"

service="$stage/service"
mkdir -p "$service"
for name in index.php admin.php become.php cancel.php cron.php guide.php robots.txt .htaccess web.config api assets install src lib migrations resources LICENSE; do
    cp -R "$root/$name" "$service/$name"
done

page="$stage/page"
mkdir -p "$page"
cp -R "$root/client/." "$page/"
# That deny rule is for a service site that also contains the client folder.
# The page zip is uploaded on its own and must stay readable.
rm -f "$page/.htaccess"

pack() {
    dir=$1
    dest=$2
    rm -f "$dest"
    (
        cd "$dir"
        find . -type f ! -name '.DS_Store' | sed 's|^\./||' | zip -q -X -@ "$dest"
    )
}

# The full archive keeps one top folder so it does not spill into whatever directory it is unpacked in.
rm -f "$out/last-words-$version.zip"
(
    cd "$stage"
    find "last-words-$version" -type f ! -name '.DS_Store' | zip -q -X -@ "$out/last-words-$version.zip"
)
pack "$service" "$out/last-words-$version-service.zip"
pack "$page" "$out/last-words-$version-page.zip"

echo "Wrote version $version to $out"
echo "  last-words-$version.zip"
echo "  last-words-$version-service.zip"
echo "  last-words-$version-page.zip"
