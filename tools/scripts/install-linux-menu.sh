#!/usr/bin/env sh
set -e
CANTO="${1:-$(cd "$(dirname "$0")/../.." && pwd)/target/release/canto}"
[ -x "$CANTO" ] || { echo "canto binary not found: $CANTO"; exit 1; }

write_script() {
  dir="$1"; var="$2"; verb="$3"; label="$4"
  mkdir -p "$dir"
  file="$dir/$label"
  {
    echo '#!/bin/sh'
    echo "target=\$(printf '%s\n' \"\$$var\" | head -n 1)"
    echo "[ -d \"\$target\" ] || exit 0"
    echo "exec \"$CANTO\" $verb \"\$target\""
  } > "$file"
  chmod +x "$file"
}

for pair in "$HOME/.local/share/nautilus/scripts:NAUTILUS_SCRIPT_SELECTED_FILE_PATHS" "$HOME/.local/share/nemo/scripts:NEMO_SCRIPT_SELECTED_FILE_PATHS"; do
  dir="${pair%%:*}"; var="${pair##*:}"
  write_script "$dir" "$var" lock "Lock with Canto"
  write_script "$dir" "$var" unlock "Unlock with Canto"
done

mkdir -p "$HOME/.local/share/kio/servicemenus"
cat > "$HOME/.local/share/kio/servicemenus/canto.desktop" <<DESKTOP
[Desktop Entry]
Type=Service
MimeType=inode/directory;
Actions=lock;unlock;
X-KDE-Submenu=Canto

[Desktop Action lock]
Name=Lock with Canto
Exec="$CANTO" lock %f

[Desktop Action unlock]
Name=Unlock with Canto
Exec="$CANTO" unlock %f
DESKTOP
chmod +x "$HOME/.local/share/kio/servicemenus/canto.desktop"
echo "Installed right-click entries for Files (Nautilus), Nemo and Dolphin."
