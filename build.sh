#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1) secure-join
cd "$ROOT/thirdparty/secure-join"
python3 build.py -DSODIUM_MONTGOMERY=false --install="$ROOT/thirdparty/install/secure-join"

# 2) volepsi
cd "$ROOT/thirdparty/volepsi"
python3 build.py --install="$ROOT/thirdparty/install/volepsi"

# 3) Kunlun
cd "$ROOT/thirdparty/Kunlun"
mkdir -p build
cd build
cmake ..
cmake --build . -j

# 4) top-level
cd "$ROOT"
mkdir -p build
cd build
cmake ..
cmake --build . -j
EOF