#!/usr/bin/env bash
set -euo pipefail

install_root="${XDG_DATA_HOME:-$HOME/.local/share}/open-osint-kit"
venv_dir="$install_root/venv"
bin_dir="$HOME/.local/bin"
wrapper="$bin_dir/osint-kit"

if [[ -f "$install_root/path-config" ]]; then
    shell_config="$(<"$install_root/path-config")"
    case "$shell_config" in
        "$HOME/.bashrc"|"$HOME/.zshrc"|"$HOME/.profile")
            printf -v escaped_bin_dir '%q' "$bin_dir"
            path_line="export PATH=$escaped_bin_dir:\$PATH"
            if [[ -f "$shell_config" ]]; then
                temp_config="$(mktemp "${shell_config}.XXXXXX")"
                if awk -v path_line="$path_line" '$0 != path_line' "$shell_config" > "$temp_config"; then
                    mv -- "$temp_config" "$shell_config"
                else
                    rm -f -- "$temp_config"
                    printf 'No se pudo actualizar %s; revisa manualmente la línea de PATH.\n' "$shell_config" >&2
                    exit 1
                fi
            fi
            ;;
        *)
            printf 'Se conserva el archivo de shell no reconocido guardado en path-config.\n' >&2
            ;;
    esac
else
    printf 'No hay registro de una línea PATH añadida por esta instalación; se conserva la configuración del shell.\n'
fi

if [[ -f "$wrapper" ]]; then
    printf -v expected_wrapper '#!/usr/bin/env bash\nexec %q "$@"' "$venv_dir/bin/osint-kit"
    actual_wrapper="$(<"$wrapper")"
    if [[ "$actual_wrapper" == "$expected_wrapper" ]]; then
        rm -- "$wrapper"
    else
        printf 'Se conserva %s porque no coincide con el lanzador generado por el instalador.\n' "$wrapper"
    fi
fi

if [[ -d "$venv_dir" ]]; then
    rm -rf -- "$venv_dir"
fi
rm -f -- "$install_root/path-config"
rmdir -- "$install_root" 2>/dev/null || true

printf 'Open OSINT Kit fue desinstalado. Se conservaron otros archivos y herramientas del usuario.\n'
printf 'Abre una terminal nueva para aplicar cualquier cambio de PATH.\n'
