#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if command -v python3 >/dev/null 2>&1; then
    python_command="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    python_command="$(command -v python)"
else
    printf '%s\n' "Python 3.9+ was not found. Install it, then run this script again." >&2
    exit 1
fi
base_python="$("$python_command" -c 'import sys; print(getattr(sys, "_base_executable", sys.executable))')"

install_root="${XDG_DATA_HOME:-$HOME/.local/share}/open-osint-kit"
venv_dir="$install_root/venv"
mkdir -p "$install_root"
"$base_python" -m venv "$venv_dir"
"$venv_dir/bin/python" -m pip install --upgrade --force-reinstall "$script_dir"

bin_dir="$HOME/.local/bin"
mkdir -p "$bin_dir"
printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$venv_dir/bin/osint-kit" > "$bin_dir/osint-kit"
chmod +x "$bin_dir/osint-kit"
export PATH="$bin_dir:$PATH"

case "${SHELL##*/}" in
    bash) shell_config="$HOME/.bashrc" ;;
    zsh) shell_config="$HOME/.zshrc" ;;
    *) shell_config="$HOME/.profile" ;;
esac
printf -v escaped_bin_dir '%q' "$bin_dir"
path_line="export PATH=$escaped_bin_dir:\$PATH"
if [[ ! -f "$shell_config" ]] || ! grep -Fqx -- "$path_line" "$shell_config"; then
    printf '\n%s\n' "$path_line" >> "$shell_config"
    printf '%s\n' "$shell_config" > "$install_root/path-config"
fi

printf 'Installed. Run: osint-kit --help\n'
printf 'Isolated environment: %s.\n' "$install_root"
printf 'Added %s to PATH in %s; open a new terminal to apply it.\n' "$bin_dir" "$shell_config"