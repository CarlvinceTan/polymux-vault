#!/bin/sh
# Install Vault Autofill in Helium on macOS: the extension files, a native messaging host that
# answers from this vault, and the host manifest Helium reads.
#
# The extension itself still has to be loaded in helium://extensions (once); after that, run this
# again whenever the code changes and reload the extension.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
dest=${VAULT_AUTOFILL_HOME:-$HOME/.local/share/helium-autofill}
helium=${VAULT_HELIUM_DIR:-$HOME/Library/Application Support/net.imput.helium}
hosts="$helium/NativeMessagingHosts"
manifest="$dest/extension/manifest.json"

cargo build --release --manifest-path "$root/Cargo.toml" --bin vault --bin vault-autofill-host

mkdir -p "$dest/extension" "$hosts"
cp "$root/browser/extension/manifest.json" "$root/browser/extension/background.js" \
   "$root/browser/extension/content.js" "$root/browser/extension/webauthn.js" "$dest/extension/"

cat > "$dest/host.sh" <<EOF
#!/bin/sh
export VAULT_CLI="\${VAULT_CLI:-$root/target/release/vault}"
exec "$root/target/release/vault-autofill-host" "\$@"
EOF
chmod +x "$dest/host.sh"

# Chrome's extension id is the first 32 hex digits of the SHA-256 of the manifest's public key,
# with each hex digit mapped from 0-f to a-p.
id=$(python3 - "$manifest" <<'PY'
import base64, hashlib, json, sys
key = json.load(open(sys.argv[1]))["key"]
digest = hashlib.sha256(base64.b64decode(key)).hexdigest()[:32]
print("".join(chr(ord("a") + int(digit, 16)) for digit in digest))
PY
)
printf '%s' "$id" > "$dest/extension-id"

cat > "$hosts/dev.vault.autofill.json" <<EOF
{
  "name": "dev.vault.autofill",
  "description": "Vault Autofill",
  "path": "$dest/host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$id/"]
}
EOF
rm -f "$hosts/dev.herdr.autofill.json"

echo "Installed Vault Autofill for $id"
echo "Extension: $dest/extension"
echo "Host:      $dest/host.sh"
echo
echo "In Helium: open helium://extensions, reload 'Vault Autofill', then reload the page."
echo "If it isn't listed yet: enable Developer mode, Load unpacked, and choose"
echo "  $dest/extension"
