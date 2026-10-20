#!/bin/sh
# Only these fixed stages exist; no user-supplied command can reach the container.
set -eu

case "${1:-}" in
  resolve)
    echo "$ npm install --package-lock-only --ignore-scripts"
    npm install --package-lock-only --ignore-scripts --no-audit --no-fund
    echo "$ npm ci --ignore-scripts"
    npm ci --ignore-scripts --no-audit --no-fund
    ;;
  test)
    echo "$ npm test --if-present"
    exec npm test --if-present
    ;;
  *)
    echo "usage: depguard-entry resolve|test" >&2
    exit 64
    ;;
esac
