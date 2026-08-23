#!/usr/bin/env bash
set -e

SKILL_DIR="$HOME/.claude/skills/ida-headless-analysis"
mkdir -p "$HOME/.claude/skills"
echo "Copying skill folder to $SKILL_DIR..."
cp -r "ida-headless-analysis" "$SKILL_DIR"

echo "Searching for IDA 9.2, 9.3, or 9.4 in environment variables..."
IFS=':' read -r -a PATHS_ARRAY <<< "$(printenv | grep -i ida | cut -d= -f2 | tr '\n' ':')"
IFS=':' read -r -a SYS_PATHS <<< "$PATH"
ALL_PATHS=("${PATHS_ARRAY[@]}" "${SYS_PATHS[@]}")

IDA_FOUND=()
for p in "${ALL_PATHS[@]}"; do
    if [[ -z "$p" ]]; then continue; fi
    if echo "$p" | grep -Eq "9\.[234]" && echo "$p" | grep -iq "ida"; then
        if [ -d "$p" ]; then
            if [ -x "$p/idat" ] || [ -x "$p/idat64" ]; then
                DUP=0
                for ext in "${IDA_FOUND[@]}"; do
                    if [[ "$ext" == "$p" ]]; then DUP=1; break; fi
                done
                if [ $DUP -eq 0 ]; then
                    IDA_FOUND+=("$p")
                fi
            fi
        fi
    fi
done

SELECTED_IDA=""
if [ ${#IDA_FOUND[@]} -eq 0 ]; then
    read -p "No IDA 9.2, 9.3, or 9.4 found in environment variables. Please enter the path to the IDA folder manually: " SELECTED_IDA
elif [ ${#IDA_FOUND[@]} -eq 1 ]; then
    echo "Found IDA at: ${IDA_FOUND[0]}"
    SELECTED_IDA="${IDA_FOUND[0]}"
else
    echo "Multiple IDA installations found:"
    for i in "${!IDA_FOUND[@]}"; do
        echo "[$((i+1))] ${IDA_FOUND[$i]}"
    done
    while true; do
        read -p "Select the correct one by typing the corresponding number: " sel
        if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "${#IDA_FOUND[@]}" ]; then
            SELECTED_IDA="${IDA_FOUND[$((sel-1))]}"
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done
fi

echo "Searching for Python 3.13.* in environment variables..."
PY_FOUND=()
IFS=':' read -r -a PY_PATHS_ARRAY <<< "$(printenv | grep -i python | cut -d= -f2 | tr '\n' ':')"
ALL_PY_PATHS=("${PY_PATHS_ARRAY[@]}" "${SYS_PATHS[@]}")

for p in "${ALL_PY_PATHS[@]}"; do
    if [[ -z "$p" ]]; then continue; fi
    if [ -d "$p" ]; then
        for py_exe in "$p/python" "$p/python3" "$p/python3.13"; do
            if [ -x "$py_exe" ]; then
                ver=$("$py_exe" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
                if [ "$ver" = "3.13" ]; then
                    DUP=0
                    for ext in "${PY_FOUND[@]}"; do
                        if [[ "$ext" == "$py_exe" ]]; then DUP=1; break; fi
                    done
                    if [ $DUP -eq 0 ]; then
                        PY_FOUND+=("$py_exe")
                    fi
                fi
            fi
        done
    elif [ -x "$p" ] && echo "$p" | grep -iq "python"; then
        ver=$("$p" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
        if [ "$ver" = "3.13" ]; then
            DUP=0
            for ext in "${PY_FOUND[@]}"; do
                if [[ "$ext" == "$p" ]]; then DUP=1; break; fi
            done
            if [ $DUP -eq 0 ]; then
                PY_FOUND+=("$p")
            fi
        fi
    fi
done

SELECTED_PY=""
if [ ${#PY_FOUND[@]} -eq 0 ]; then
    read -p "No Python 3.13.* found. Please enter the path to the python binary manually: " SELECTED_PY
elif [ ${#PY_FOUND[@]} -eq 1 ]; then
    echo "Found Python at: ${PY_FOUND[0]}"
    SELECTED_PY="${PY_FOUND[0]}"
else
    echo "Multiple Python 3.13.* installations found:"
    for i in "${!PY_FOUND[@]}"; do
        echo "[$((i+1))] ${PY_FOUND[$i]}"
    done
    while true; do
        read -p "Select the correct one by typing the corresponding number: " sel
        if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "${#PY_FOUND[@]}" ]; then
            SELECTED_PY="${PY_FOUND[$((sel-1))]}"
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done
fi

echo "Replacing variables in $SKILL_DIR..."
# Escape variables for sed
ESC_PY=$(echo "$SELECTED_PY" | sed -e 's/[\/&]/\\&/g')
ESC_IDA=$(echo "$SELECTED_IDA" | sed -e 's/[\/&]/\\&/g')

find "$SKILL_DIR" -type f -exec sed -i "s/%PYTHON_BIN_PATH%/$ESC_PY/g" {} +
find "$SKILL_DIR" -type f -exec sed -i "s/%IDA_PATH%/$ESC_IDA/g" {} +

export IDADIR="$SELECTED_IDA"

echo "Installing/Upgrading ida-domain module..."
"$SELECTED_PY" -m pip install --upgrade "ida-domain>=0.5.0,<0.6.0"

echo "Installing requirements from requirements.txt..."
if [ -f "requirements.txt" ]; then
    "$SELECTED_PY" -m pip install -r "requirements.txt"
fi

if ! "$SELECTED_PY" -c "import ida_domain, idapro; print('ida-domain/idapro import OK')"; then
    echo "IDA Python verification failed"
    exit 1
fi

echo "Setup complete. IDADIR=$IDADIR"
echo "Skill installed to $SKILL_DIR"
