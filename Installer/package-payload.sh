#!/bin/bash
set -euo pipefail

# pkgutil expands a component directly, but a product archive nests it under
# the original component filename. Accept only the two layouts we produce.
[[ $# -eq 1 ]] || { /bin/echo "Usage: $0 <expanded-package>" >&2; exit 1; }
payload=""
for candidate in "$1/Payload" "$1/MacSSHManager-component.pkg/Payload"; do
    if [[ -d "${candidate}" && ! -L "${candidate}" ]]; then
        [[ -z "${payload}" ]] || { /bin/echo "Ambiguous package payload" >&2; exit 1; }
        payload="${candidate}"
    fi
done
[[ -n "${payload}" ]] || { /bin/echo "Expected package payload is missing" >&2; exit 1; }
/bin/echo "${payload}"
