#!/usr/bin/env bash
#
# Deploys the chart for real into a throwaway local cluster (k3s inside Docker, via k3d)
# and runs its `helm test` hook. This is the layer the unit-level chart test cannot reach:
# admission (the namespace enforces the "restricted" Pod Security level), probes actually
# turning green on the distroless image with a read-only root, the hook Job sequencing,
# and an upgrade on top of an existing release. Local only, about a minute.
#
#   npm run build && docker build -t lasuite/encryption:smoke .
#   deploy/helm/smoke-k3d.sh                # uses lasuite/encryption:smoke
#   IMAGE_TAG=1.2.3 deploy/helm/smoke-k3d.sh # a tag pulled from Docker Hub instead
#   KEEP=1 deploy/helm/smoke-k3d.sh          # leave the cluster up to poke at it
#
# Needs docker, k3d, kubectl and helm. No database is involved: migrations are disabled
# and the server only connects when a request needs it, so /health is green without one.
set -euo pipefail

CLUSTER=${CLUSTER:-encryption-smoke}
NAMESPACE=encryption
RELEASE=enc
IMAGE_TAG=${IMAGE_TAG:-smoke}
CHART="$(cd "$(dirname "$0")" && pwd)/encryption"

for tool in docker k3d kubectl helm; do
  command -v "$tool" > /dev/null || { echo "missing: $tool" >&2; exit 1; }
done

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    echo "Cluster kept: kubectl --context k3d-${CLUSTER} -n ${NAMESPACE} get all"
  else
    k3d cluster delete "$CLUSTER" > /dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

k3d cluster delete "$CLUSTER" > /dev/null 2>&1 || true
k3d cluster create "$CLUSTER" --wait --timeout 120s --no-lb --k3s-arg '--disable=traefik@server:0'
export KUBECONFIG
KUBECONFIG="$(k3d kubeconfig write "$CLUSTER")"

# A locally built image is imported straight into the cluster; anything else is pulled.
if docker image inspect "lasuite/encryption:${IMAGE_TAG}" > /dev/null 2>&1; then
  k3d image import "lasuite/encryption:${IMAGE_TAG}" --cluster "$CLUSTER"
fi

kubectl create namespace "$NAMESPACE"
# What a hardened cluster enforces. The chart's defaults must pass it.
kubectl label namespace "$NAMESPACE" \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted

install() {
  helm upgrade --install "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --values "${CHART}/ci/full-values.yaml" \
    --set image.tag="$IMAGE_TAG" \
    --set image.pullPolicy=IfNotPresent \
    --set database.migration.enabled=false \
    --set ingress.enabled=false \
    --set networkPolicy.enabled=false \
    --set replicaCount=2 \
    --wait --timeout 3m "$@"
}

echo "== install"
install
echo "== helm test"
helm test "$RELEASE" --namespace "$NAMESPACE" --logs
echo "== upgrade (revision 2, rolling update with zero unavailable)"
install --set podLabels.smoke=revision-2
helm test "$RELEASE" --namespace "$NAMESPACE" --logs

echo "== result"
kubectl -n "$NAMESPACE" get deployment,pod,service,pdb -o wide
kubectl -n "$NAMESPACE" get events --field-selector type=Warning -o custom-columns=REASON:.reason,MESSAGE:.message | sed 1d | sort -u | sed 's/^/warning: /' || true
echo "OK: ${RELEASE} deploys, answers /health and upgrades in place under the restricted Pod Security level"
