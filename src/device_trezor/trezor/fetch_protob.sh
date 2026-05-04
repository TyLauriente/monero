#!/usr/bin/env sh
set -e

cd "$(dirname "$0")"

if [ ! -d "trezor-common" ]; then
  git clone https://github.com/trezor/trezor-common.git
fi

cd trezor-common
git fetch
git reset --hard bc28c316d05bf1e9ebfe3d7df1ab25831d98d168
cd ..

rm -rf protob
mkdir protob

proto_files="messages.proto messages-common.proto messages-monero.proto messages-management.proto messages-debug.proto"

for file in ${proto_files}
do
  cp "trezor-common/protob/${file}" protob/
done
cp "trezor-common/COPYING" protob/

# Trezor Host Protocol v2 (THP) messages live in trezor-firmware (newer
# than the trezor-common pin above) so we fetch them from there. A small
# adjustment converts the import to use our existing messages.proto for
# wire_in/wire_out option definitions, and drops the (wire_enum) and
# (internal_only) tags which are only metadata for trezor-firmware's own
# build tooling and have no effect on generated wire format.
THP_REF="main"
THP_RAW="https://raw.githubusercontent.com/trezor/trezor-firmware/${THP_REF}/common/protob/messages-thp.proto"
echo "Fetching ${THP_RAW}"
curl -sL "${THP_RAW}" -o protob/messages-thp.proto
sed -i 's|^import "options.proto";|import "messages.proto";|' protob/messages-thp.proto
sed -i '/option (wire_enum) = true;/d'      protob/messages-thp.proto
sed -i '/option (internal_only) = true;/d'  protob/messages-thp.proto

cd protob
echo "Checksums:"
find . -type f -print0 | env LC_ALL=C sort -z | xargs -r0 sha256sum

