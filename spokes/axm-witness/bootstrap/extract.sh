#!/usr/bin/env bash
set -euo pipefail

bootstrap_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
destination="${1:-$(cd "$bootstrap_dir/.." && pwd)/work}"
base64_path="$bootstrap_dir/axm-witness-bootstrap.tar.gz.b64"
archive_path="$bootstrap_dir/axm-witness-bootstrap.tar.gz"

mapfile -t parts < <(
  find "$bootstrap_dir" -maxdepth 1 -type f \
    -name 'axm-witness-bootstrap.tar.gz.b64.part*' -print | LC_ALL=C sort
)

if [[ "${#parts[@]}" -ne 10 ]]; then
  printf 'expected 10 bootstrap fragments, found %s\n' "${#parts[@]}" >&2
  exit 1
fi

for index in "${!parts[@]}"; do
  expected="$(printf '%s/axm-witness-bootstrap.tar.gz.b64.part%02d' "$bootstrap_dir" "$index")"
  if [[ "${parts[$index]}" != "$expected" ]]; then
    printf 'fragment order mismatch at %s: expected %s, found %s\n' \
      "$index" "$expected" "${parts[$index]}" >&2
    exit 1
  fi
done

cat "${parts[@]}" > "$base64_path"
base64 --decode "$base64_path" > "$archive_path"
(
  cd "$bootstrap_dir"
  sha256sum --check SHA256SUMS
)

rm -rf "$destination"
mkdir -p "$destination"
tar --extract --gzip --file "$archive_path" --directory "$destination" --no-same-owner

test -f "$destination/axm-witness/pyproject.toml"
test -f "$destination/axm-witness/verifiers/go/go.mod"
printf 'reconstructed axm-witness at %s\n' "$destination/axm-witness"
