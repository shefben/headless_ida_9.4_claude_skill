#!/usr/bin/env bash
set -euo pipefail

IDA_PATH_ARG=""
PYTHON_PATH_ARG=""

usage() {
    cat <<'EOF'
Usage: ./setup.sh [options]

Options:
  --ida-path PATH, --IdaPath PATH, -IdaPath PATH
      Explicit IDA installation directory. Equivalent to PowerShell -IdaPath.

  --python-path PATH, --PythonPath PATH, -PythonPath PATH
      Explicit Python 3.13 executable. Equivalent to PowerShell -PythonPath.

  -h, --help
      Show this help text.

Examples:
  ./setup.sh
  ./setup.sh --ida-path /opt/ida-9.4 --python-path /usr/bin/python3.13
  ./setup.sh --IdaPath "$HOME/tools/ida-9.4" --PythonPath "$HOME/.pyenv/versions/3.13.7/bin/python"
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ida-path|--IdaPath|-IdaPath)
            [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
            IDA_PATH_ARG="$2"
            shift 2
            ;;
        --ida-path=*|--IdaPath=*)
            IDA_PATH_ARG="${1#*=}"
            shift
            ;;
        --python-path|--PythonPath|-PythonPath)
            [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
            PYTHON_PATH_ARG="$2"
            shift 2
            ;;
        --python-path=*|--PythonPath=*)
            PYTHON_PATH_ARG="${1#*=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
SOURCE_SKILL_DIR="$SCRIPT_DIR/ida-headless-analysis"
REQUIREMENTS_FILE="$SCRIPT_DIR/requirements.txt"
SKILLS_ROOT="$HOME/.claude/skills"
SKILL_DIR="$SKILLS_ROOT/ida-headless-analysis"

normalize_path() {
    local p="${1:-}"
    [[ -n "$p" ]] || return 1
    p="${p/#\~/$HOME}"

    if [[ -e "$p" ]]; then
        if command -v realpath >/dev/null 2>&1; then
            realpath "$p"
            return
        fi
        if command -v python3 >/dev/null 2>&1; then
            python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$p"
            return
        fi
    fi

    printf '%s\n' "${p%/}"
}

is_ida_dir() {
    local d="${1:-}"
    [[ -d "$d" ]] || return 1
    local exe
    for exe in ida ida64 idat idat64; do
        [[ -x "$d/$exe" ]] && return 0
    done
    return 1
}

ida_version_from_path() {
    local p="${1:-}"
    local base
    base="$(basename "$p")"
    if [[ "$p" =~ (^|[^0-9])(9\.[1-4])([^0-9]|$) ]]; then
        printf '%s\n' "${BASH_REMATCH[2]}"
        return
    fi
    if [[ "$base" =~ [Ii][Dd][Aa]([^0-9]*)(9)[_.-]?([1-4])([^0-9]|$) ]]; then
        printf '9.%s\n' "${BASH_REMATCH[3]}"
        return
    fi
    printf 'unknown\n'
}

IDA_PATHS=()
IDA_VERSIONS=()
IDA_SOURCES=()

add_ida() {
    local raw="${1:-}"
    local source="${2:-unknown}"
    [[ -n "$raw" ]] || return 0

    local p="$raw"
    if [[ -f "$p" ]]; then
        p="$(dirname "$p")"
    fi
    is_ida_dir "$p" || return 0
    p="$(normalize_path "$p")"
    p="${p%/}"

    local i
    for i in "${!IDA_PATHS[@]}"; do
        if [[ "${IDA_PATHS[$i]}" == "$p" ]]; then
            if [[ ",${IDA_SOURCES[$i]}," != *",$source,"* ]]; then
                IDA_SOURCES[$i]="${IDA_SOURCES[$i]},$source"
            fi
            return 0
        fi
    done

    IDA_PATHS+=("$p")
    IDA_VERSIONS+=("$(ida_version_from_path "$p")")
    IDA_SOURCES+=("$source")
}

scan_ida_children() {
    local base="${1:-}"
    local depth="${2:-1}"
    local source="${3:-filesystem}"
    [[ -d "$base" ]] || return 0

    local child grandchild name
    shopt -s nullglob
    for child in "$base"/*; do
        [[ -d "$child" ]] || continue
        name="$(basename "$child")"
        if [[ "$name" =~ [Ii][Dd][Aa] ]] || [[ "$name" =~ [Hh]ex.?[Rr]ays ]]; then
            add_ida "$child" "$source"
            if (( depth > 1 )); then
                for grandchild in "$child"/*; do
                    [[ -d "$grandchild" ]] || continue
                    add_ida "$grandchild" "$source"
                done
            fi
        fi
    done
    shopt -u nullglob
}

add_python() {
    local p="${1:-}"
    [[ -n "$p" && -x "$p" && -f "$p" ]] || return 0

    local ver
    ver="$("$p" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)"
    [[ "$ver" == "3.13" ]] || return 0
    p="$(normalize_path "$p")"

    local existing
    for existing in "${PY_FOUND[@]:-}"; do
        [[ "$existing" == "$p" ]] && return 0
    done
    PY_FOUND+=("$p")
}

if [[ ! -d "$SOURCE_SKILL_DIR" ]]; then
    echo "Skill source folder was not found: $SOURCE_SKILL_DIR" >&2
    exit 1
fi

mkdir -p "$SKILLS_ROOT"
echo "Installing skill folder to $SKILL_DIR..."
rm -rf -- "$SKILL_DIR"
cp -R -- "$SOURCE_SKILL_DIR" "$SKILL_DIR"

echo "Searching for IDA 9.1 through 9.4 installations..."

if [[ -n "$IDA_PATH_ARG" ]]; then
    add_ida "$IDA_PATH_ARG" "argument"
    if [[ ${#IDA_PATHS[@]} -eq 0 ]]; then
        echo "--ida-path does not point to a valid IDA installation: $IDA_PATH_ARG" >&2
        exit 1
    fi
else
    while IFS='=' read -r name value; do
        [[ "$name" =~ [Ii][Dd][Aa] || "$value" =~ [Ii][Dd][Aa] ]] || continue
        IFS=':' read -r -a parts <<< "$value"
        for p in "${parts[@]}"; do
            add_ida "$p" "environment"
        done
    done < <(printenv)

    IFS=':' read -r -a PATH_PARTS <<< "${PATH:-}"
    for p in "${PATH_PARTS[@]}"; do
        add_ida "$p" "PATH"
    done

    parents=()
    for p in "${IDA_PATHS[@]:-}"; do
        [[ -n "$p" ]] || continue
        parent="$(dirname "$p")"
        duplicate=0
        for existing in "${parents[@]:-}"; do
            [[ "$existing" == "$parent" ]] && duplicate=1 && break
        done
        (( duplicate == 0 )) && parents+=("$parent")
    done
    for parent in "${parents[@]:-}"; do
        [[ -n "$parent" ]] || continue
        scan_ida_children "$parent" 1 "sibling-scan"
    done

    for base in \
        /opt /usr/local /Applications \
        "$HOME" "$HOME/opt" "$HOME/tools" "$HOME/Tools" "$HOME/apps" "$HOME/Applications" \
        "$HOME/.local" "$HOME/.local/opt"; do
        scan_ida_children "$base" 2 "common-location"
    done
fi

if [[ ${#IDA_PATHS[@]} -eq 0 ]]; then
    read -r -p "No IDA installation was found automatically. Enter the IDA 9.4 folder: " manual_ida
    add_ida "$manual_ida" "manual"
    if [[ ${#IDA_PATHS[@]} -eq 0 ]]; then
        echo "The entered path is not a valid IDA installation: $manual_ida" >&2
        exit 1
    fi
fi

rank_version() {
    case "$1" in
        9.4) echo 0 ;;
        9.3) echo 1 ;;
        9.2) echo 2 ;;
        9.1) echo 3 ;;
        *) echo 4 ;;
    esac
}

SORTED_INDICES=()
while IFS= read -r idx; do
    [[ -n "$idx" ]] && SORTED_INDICES+=("$idx")
done < <(
    for i in "${!IDA_PATHS[@]}"; do
        printf '%s\t%s\t%s\n' "$(rank_version "${IDA_VERSIONS[$i]}")" "${IDA_PATHS[$i]}" "$i"
    done | sort -t $'\t' -k1,1n -k2,2 | cut -f3
)

echo "Discovered IDA installations:"
for display_i in "${!SORTED_INDICES[@]}"; do
    idx="${SORTED_INDICES[$display_i]}"
    printf '[%d] IDA %-7s %s  (%s)\n' "$((display_i + 1))" "${IDA_VERSIONS[$idx]}" "${IDA_PATHS[$idx]}" "${IDA_SOURCES[$idx]}"
done

SELECTED_INDEX=""
IDA94_INDICES=()
for idx in "${SORTED_INDICES[@]}"; do
    [[ "${IDA_VERSIONS[$idx]}" == "9.4" ]] && IDA94_INDICES+=("$idx")
done

if [[ -n "$IDA_PATH_ARG" ]]; then
    SELECTED_INDEX="${SORTED_INDICES[0]}"
elif [[ ${#IDA94_INDICES[@]} -eq 1 ]]; then
    SELECTED_INDEX="${IDA94_INDICES[0]}"
    echo "Automatically selected the discovered IDA 9.4 installation: ${IDA_PATHS[$SELECTED_INDEX]}"
elif [[ ${#SORTED_INDICES[@]} -eq 1 ]]; then
    SELECTED_INDEX="${SORTED_INDICES[0]}"
    echo "Found IDA at: ${IDA_PATHS[$SELECTED_INDEX]}"
else
    while true; do
        read -r -p "Select the IDA installation by typing its number (IDA 9.4 is recommended): " sel
        if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#SORTED_INDICES[@]} )); then
            SELECTED_INDEX="${SORTED_INDICES[$((sel - 1))]}"
            break
        fi
        echo "Invalid selection. Please try again."
    done
fi

SELECTED_IDA="${IDA_PATHS[$SELECTED_INDEX]%/}"
SELECTED_IDA_VERSION="${IDA_VERSIONS[$SELECTED_INDEX]}"
echo "Using canonical IDA path: $SELECTED_IDA"
echo "Detected IDA version: $SELECTED_IDA_VERSION"
if [[ "$SELECTED_IDA_VERSION" != "9.4" ]]; then
    echo "WARNING: Selected IDA is '$SELECTED_IDA_VERSION' at $SELECTED_IDA. The skill targets IDA 9.4; older versions are fallback/testing configurations." >&2
fi

echo "Searching for Python 3.13.*..."
PY_FOUND=()
if [[ -n "$PYTHON_PATH_ARG" ]]; then
    add_python "$PYTHON_PATH_ARG"
    if [[ ${#PY_FOUND[@]} -eq 0 ]]; then
        echo "--python-path must point to a Python 3.13 executable: $PYTHON_PATH_ARG" >&2
        exit 1
    fi
else
    for command_name in python3.13 python3 python; do
        if command -v "$command_name" >/dev/null 2>&1; then
            add_python "$(command -v "$command_name")"
        fi
    done

    IFS=':' read -r -a PATH_PARTS <<< "${PATH:-}"
    for p in "${PATH_PARTS[@]}"; do
        [[ -d "$p" ]] || continue
        for py in "$p/python3.13" "$p/python3" "$p/python"; do
            add_python "$py"
        done
    done
fi

SELECTED_PY=""
if [[ ${#PY_FOUND[@]} -eq 0 ]]; then
    read -r -p "No Python 3.13.* found. Enter the path to the Python 3.13 executable: " manual_py
    add_python "$manual_py"
    if [[ ${#PY_FOUND[@]} -eq 0 ]]; then
        echo "The entered executable is not Python 3.13: $manual_py" >&2
        exit 1
    fi
fi

if [[ ${#PY_FOUND[@]} -eq 1 || -n "$PYTHON_PATH_ARG" ]]; then
    SELECTED_PY="${PY_FOUND[0]}"
    echo "Using Python at: $SELECTED_PY"
else
    echo "Multiple Python 3.13.* installations found:"
    for i in "${!PY_FOUND[@]}"; do
        echo "[$((i + 1))] ${PY_FOUND[$i]}"
    done
    while true; do
        read -r -p "Select the Python installation by typing its number: " sel
        if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#PY_FOUND[@]} )); then
            SELECTED_PY="${PY_FOUND[$((sel - 1))]}"
            break
        fi
        echo "Invalid selection. Please try again."
    done
fi

PY_VER="$("$SELECTED_PY" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")"
if [[ "$PY_VER" != "3.13" ]]; then
    echo "Selected Python must be 3.13.x; got '$PY_VER' from $SELECTED_PY" >&2
    exit 1
fi

echo "Replacing variables in $SKILL_DIR..."
export SETUP_SELECTED_PY="$SELECTED_PY"
export SETUP_SELECTED_IDA="$SELECTED_IDA"
export SETUP_SKILL_DIR="$SKILL_DIR"
"$SELECTED_PY" - <<'PY'
from pathlib import Path
import os

root = Path(os.environ["SETUP_SKILL_DIR"])
py = os.environ["SETUP_SELECTED_PY"]
ida = os.environ["SETUP_SELECTED_IDA"]
text_ext = {".md", ".py", ".json", ".txt", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".ps1", ".sh"}
for path in root.rglob("*"):
    if not path.is_file() or path.suffix.lower() not in text_ext:
        continue
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    new = content.replace("%PYTHON_BIN_PATH%", py).replace("%IDA_PATH%", ida)
    if new != content:
        path.write_text(new, encoding="utf-8")
PY

export IDADIR="$SELECTED_IDA"
export IDAPYTHON_DYNLOAD_BASE="$SELECTED_IDA"

echo "Installing/Upgrading ida-domain module..."
"$SELECTED_PY" -m pip install --upgrade "ida-domain>=0.5.0,<0.6.0"

echo "Installing requirements from requirements.txt..."
if [[ -f "$REQUIREMENTS_FILE" ]]; then
    "$SELECTED_PY" -m pip install -r "$REQUIREMENTS_FILE"
fi

echo "Verifying ida-domain/idapro imports with IDADIR=$IDADIR..."
if ! "$SELECTED_PY" -c "import ida_domain, idapro; print('ida-domain/idapro import OK')"; then
    echo "IDA Python verification failed" >&2
    exit 1
fi

echo "Setup complete. IDADIR=$IDADIR"
echo "Skill installed to $SKILL_DIR"
