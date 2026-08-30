#!/usr/bin/env bash
#
# Build and publish gaslight to PyPI using an API token stored in macOS Keychain.
#
# One-time setup (run once; use a FRESH token and revoke any old/leaked one):
#     security add-generic-password -a "$USER" -s pypi-gaslight -w 'pypi-<your-token>'
#
# Then release with:   scripts/release.sh        (or the `gaslight-release` alias)
# Preview with:        scripts/release.sh --dry-run
#
# The token never lives in the repo or a dotfile — it is read from Keychain at
# publish time and passed to uv only via the environment for that one command.
# The script also REFUSES to publish an sdist that contains anything but the
# package + metadata, so an internal/secret file can never be shipped (the leak
# class fixed in 0.2.4).
set -euo pipefail

KEYCHAIN_SERVICE="pypi-gaslight"
# The only non-package files allowed in the source distribution.
ALLOWED_META="README.md LICENSE CONTRIBUTING.md pyproject.toml PKG-INFO .gitignore"

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

# Always operate from the repo root (this script lives in scripts/).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# 1. Token from Keychain.
if ! TOKEN="$(security find-generic-password -s "$KEYCHAIN_SERVICE" -w 2>/dev/null)"; then
  cat >&2 <<EOF
✗ No PyPI token in Keychain (service: $KEYCHAIN_SERVICE).
  Store it once — use a FRESH token, and revoke any old/leaked one:
    security add-generic-password -a "\$USER" -s $KEYCHAIN_SERVICE -w 'pypi-<your-token>'
EOF
  exit 1
fi

# 2. Clean build.
echo "→ building…"
rm -rf dist
uv build >/dev/null
VERSION="$(ls dist/gaslight-*.tar.gz | sed -E 's|.*/gaslight-(.*)\.tar\.gz|\1|')"

# 3. Safety gate — the sdist must contain ONLY the package + known metadata.
echo "→ checking sdist contents…"
unexpected=""
while IFS= read -r entry; do
  rel="${entry#gaslight-$VERSION/}"
  [[ -z "$rel" || "$rel" == */ ]] && continue          # skip dir entries
  [[ "$rel" == src/gaslight/* ]] && continue           # the package itself
  skip=0
  for m in $ALLOWED_META; do [[ "$rel" == "$m" ]] && { skip=1; break; }; done
  [[ "$skip" == 1 ]] && continue
  unexpected+="  $rel"$'\n'
done < <(tar tzf "dist/gaslight-$VERSION.tar.gz")

if [[ -n "$unexpected" ]]; then
  {
    echo "✗ REFUSING TO PUBLISH — the sdist contains files outside the package/metadata whitelist:"
    printf '%s' "$unexpected"
    echo "  These could leak internal or secret material. Fix the sdist whitelist in"
    echo "  [tool.hatch.build.targets.sdist] (pyproject.toml) before publishing."
  } >&2
  exit 1
fi
echo "  ✓ sdist clean — package + metadata only"

# 4. Publish (or preview).
if [[ "$DRY_RUN" == 1 ]]; then
  echo "→ DRY RUN — would publish gaslight $VERSION:"
  ls -1 dist/
  exit 0
fi

printf "→ publish gaslight %s to PyPI? this is IRREVERSIBLE [y/N] " "$VERSION"
read -r reply
[[ "$reply" == [yY] || "$reply" == [yY][eE][sS] ]] || { echo "aborted."; exit 1; }

# --check-url lets a re-run skip files already on the index instead of erroring.
UV_PUBLISH_TOKEN="$TOKEN" uv publish --check-url https://pypi.org/simple/gaslight/
echo "✓ published gaslight $VERSION — verify with:  uvx gaslight@$VERSION --help"
