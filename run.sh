#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
mix deps.get
exec mix run --no-halt
