#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

eval "$(minikube docker-env)"

docker build -f platform/Dockerfile \
  --build-arg SERVICE_TARGET=notification_gateway \
  -t mtnp-gateway:local .

docker build -f platform/Dockerfile \
  --build-arg SERVICE_TARGET=notification_dispatcher \
  -t mtnp-dispatcher:local .

docker build -f platform/Dockerfile \
  --build-arg SERVICE_TARGET=notification_storage \
  --build-arg INSTALL_CASSANDRA_TOOLS=true \
  -t mtnp-storage:local .

echo "Built minikube-local images:"
echo "  mtnp-gateway:local"
echo "  mtnp-dispatcher:local"
echo "  mtnp-storage:local"
