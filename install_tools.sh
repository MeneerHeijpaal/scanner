#!/usr/bin/env bash
set -euo pipefail

# The script's current working directory, not the script's own directory
INSTALL_DIR="$(pwd)/bin"
PLATFORM="macOS_arm64"
TMP_DIR="$(mktemp -d)"

trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$INSTALL_DIR"

command -v curl >/dev/null 2>&1 || {
    echo "Error: curl is required." >&2
    exit 1
}

command -v unzip >/dev/null 2>&1 || {
    echo "Error: unzip is required." >&2
    exit 1
}

download_tool() {
    local repo="$1"
    local binary="$2"

    echo "Checking latest version of ${binary}..."

    local release_json
    release_json="$(
        curl -fsSL \
            -H "Accept: application/vnd.github+json" \
            "https://api.github.com/repos/${repo}/releases/latest"
    )"

    local tag
    tag="$(
        printf '%s\n' "$release_json" |
        sed -n 's/.*"tag_name": "\(v[^"]*\)".*/\1/p' |
        head -n 1
    )"

    if [[ -z "$tag" ]]; then
        echo "Error: could not determine the latest version of ${binary}." >&2
        exit 1
    fi

    local version="${tag#v}"
    local asset="${binary}_${version}_${PLATFORM}.zip"
    local url="https://github.com/${repo}/releases/download/${tag}/${asset}"
    local archive="${TMP_DIR}/${asset}"
    local extract_dir="${TMP_DIR}/${binary}"

    echo "Downloading ${binary} ${tag}..."
    curl -fL "$url" -o "$archive"

    mkdir -p "$extract_dir"
    unzip -q -o "$archive" -d "$extract_dir"

    # Find the executable in case the ZIP contains a directory
    local executable
    executable="$(find "$extract_dir" -type f -name "$binary" -print -quit)"

    if [[ -z "$executable" ]]; then
        echo "Error: executable '${binary}' was not found in ${asset}." >&2
        exit 1
    fi

    install -m 0755 "$executable" "${INSTALL_DIR}/${binary}"

    echo "Installed ${binary} ${tag} -> ${INSTALL_DIR}/${binary}"
}

download_tool "projectdiscovery/nuclei" "nuclei"
download_tool "projectdiscovery/naabu" "naabu"
download_tool "projectdiscovery/httpx" "httpx"
download_tool "projectdiscovery/interactsh" "interactsh-client"

echo
echo "All tools were installed in:"
echo "  ${INSTALL_DIR}"
