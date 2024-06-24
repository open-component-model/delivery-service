#!/usr/bin/env bash

set -euo pipefail

CLUSTER_NAME=""

parse_flags() {
  while test $# -gt 0; do
    case "$1" in
    --cluster-name)
      shift; CLUSTER_NAME="$1"
      ;;
    esac

    shift
  done
}

parse_flags "$@"

kind delete cluster \
  --name "$CLUSTER_NAME"
