#!/bin/sh
# Remove Vault Autofill's native messaging host. The extension stays installed in Helium until it
# is removed or turned off at helium://extensions.
#
# --purge also removes the installed extension files in ~/.local/share/helium-autofill.
set -eu

dest=${VAULT_AUTOFILL_HOME:-$HOME/.local/share/helium-autofill}
helium=${VAULT_HELIUM_DIR:-$HOME/Library/Application Support/net.imput.helium}
hosts="$helium/NativeMessagingHosts"

rm -f "$hosts/dev.vault.autofill.json" "$hosts/dev.herdr.autofill.json"
if [ "${1:-}" = "--purge" ]; then
  rm -rf "$dest"
fi

echo "Removed the Vault Autofill host manifest."
[ "${1:-}" = "--purge" ] && echo "Removed $dest."
echo "Turn the extension off or remove it at helium://extensions."
