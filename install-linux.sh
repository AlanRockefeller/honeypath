#!/usr/bin/env bash
set -euo pipefail

# A checkout may live on SSHFS/FUSE, where the mounting user can read it but
# local root cannot.  Stage the small runtime into persistent local storage
# before sudo starts Python.  The installed service remains unprivileged and
# deliberately runs this target-user-owned copy.
source_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
data_root=${XDG_DATA_HOME:-"$HOME/.local/share"}
install_dir="$data_root/honeypath"
target_user=$(id -un)

if [[ "$source_dir" != "$install_dir" ]]; then
  mkdir -p -- "$install_dir"
  cp -a -- "$source_dir/honeypath" "$install_dir/"
  cp -a -- "$source_dir/honeypath.py" "$install_dir/"
fi

printf 'Staged Honeypath runtime at %s\n' "$install_dir"
exec sudo python3 "$install_dir/honeypath.py" install-linux \
  --user "$target_user" "$@"
