#!/usr/bin/env bash
# Download the self-hosted fonts into static/fonts/.
#
# Icons use a *subset* of Material Symbols Rounded: only the glyphs listed in
# ICONS are included (~30 KB instead of ~3 MB). If you use a new icon name in a
# template or script, add it here and re-run this script.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=static/fonts
UA="Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"

ICONS=(
  add arrow_back arrow_downward arrow_upward article badge cancel check
  check_circle chevron_right close cloud code create_new_folder dark_mode
  database delete description download draft drive_file_move
  drive_folder_upload edit error expand_less expand_more folder folder_open
  folder_zip grid_view group group_add groups image key light_mode lock logout
  menu more_vert movie music_note person_add person_remove picture_as_pdf
  schedule search settings shield slideshow table_chart upload upload_file
  view_list visibility workspaces
)
NAMES=$(printf '%s\n' "${ICONS[@]}" | sort -u | paste -sd, -)

fetch_css() { curl -fsS -A "$UA" "$1"; }
first_woff2() { grep -o 'url(https://[^)]*)' | head -1 | sed 's/^url(//; s/)$//'; }

# Material Symbols Rounded, FILL axis kept so active nav items can use filled icons.
url=$(fetch_css "https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..24,400,0..1,0&icon_names=${NAMES}&display=block" | first_woff2)
curl -fsS "$url" -o "$OUT/material-symbols-rounded.woff2"

# Roboto (variable weight), latin subset.
css=$(fetch_css "https://fonts.googleapis.com/css2?family=Roboto:wght@400..700&display=swap")
url=$(printf '%s' "$css" | awk '/\/\* latin \*\//{f=1} f && /woff2/{print; exit}' | grep -o 'url(https://[^)]*)' | sed 's/^url(//; s/)$//')
curl -fsS "$url" -o "$OUT/roboto-latin.woff2"

ls -l "$OUT"
