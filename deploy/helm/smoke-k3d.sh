#!/usr/bin/env bash
#
# Deploys the chart for real into a throwaway local cluster (k3s inside Docker, via k3d)
# and runs its `helm test` hook. This is the layer the unit-level chart test cannot reach:
# admission (the namespace enforces the "restricted" Pod Security level), probes actually
# turning green on the distroless image with a read-only root, the migration hook against
# a real PostgreSQL with the two roles from deploy/postgres/, and an upgrade on top of an
# existing release that rotates the migrator's password. Local only, a couple of minutes.
#
#   npm run build && docker build -t lasuite/encryption:smoke .
#   deploy/helm/smoke-k3d.sh                # uses lasuite/encryption:smoke
#   IMAGE_TAG=1.2.3 deploy/helm/smoke-k3d.sh # a tag pulled from Docker Hub instead
#   KEEP=1 deploy/helm/smoke-k3d.sh          # leave the cluster up to poke at it
#
# Needs docker, k3d, kubectl and helm.
set -euo pipefail

CLUSTER=${CLUSTER:-encryption-smoke}
NAMESPACE=encryption
RELEASE=enc
IMAGE_TAG=${IMAGE_TAG:-smoke}
CHART="$(cd "$(dirname "$0")" && pwd)/encryption"
ROLES="$(cd "$(dirname "$0")/../postgres" && pwd)"
# The server's PostgreSQL, pinned like in docker-compose.yaml.
POSTGRES_IMAGE=postgres:16.4@sha256:e62fbf9d3e2b49816a32c400ed2dba83e3b361e6833e624024309c35d334b412

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

# PostgreSQL in a namespace of its own: the official image runs as root, which the
# restricted level below would refuse, and the database is not what is under test.
kubectl create namespace smoke-db
kubectl -n smoke-db apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
spec:
  selector:
    matchLabels: { app: postgres }
  template:
    metadata:
      labels: { app: postgres }
    spec:
      containers:
        - name: postgres
          image: ${POSTGRES_IMAGE}
          env:
            - { name: POSTGRES_PASSWORD, value: admin }
            - { name: POSTGRES_DB, value: encryption }
          readinessProbe:
            exec: { command: [pg_isready, -U, postgres, -d, encryption] }
            periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
spec:
  selector: { app: postgres }
  ports: [{ port: 5432 }]
EOF
kubectl -n smoke-db rollout status deployment/postgres --timeout 120s

psql() {
  kubectl -n smoke-db exec -i deployment/postgres -- psql -U postgres -d encryption -v ON_ERROR_STOP=1 "$@"
}
# The documented role setup, as an operator runs it.
psql -v password="'migrator-1'" -f - < "${ROLES}/create-migrator-role.sql"
psql -v password="'runtime-1'" -f - < "${ROLES}/create-runtime-role.sql"
DB_HOST=postgres.smoke-db.svc.cluster.local:5432/encryption?schema=encryption

kubectl create namespace "$NAMESPACE"
# What a hardened cluster enforces. The chart's defaults must pass it.
kubectl label namespace "$NAMESPACE" \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted

install() {
  local migrator_password=$1
  shift
  helm upgrade --install "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --values "${CHART}/ci/full-values.yaml" \
    --set image.tag="$IMAGE_TAG" \
    --set image.pullPolicy=IfNotPresent \
    --set-string database.url="postgresql://encryption_runtime:runtime-1@${DB_HOST}" \
    --set-string database.migration.url="postgresql://encryption_migrator:${migrator_password}@${DB_HOST}" \
    --set ingress.enabled=false \
    --set networkPolicy.enabled=false \
    --set replicaCount=2 \
    --wait --timeout 3m "$@"
}

# What a successful migration hook must leave behind: the journal written by the migrator
# role, and none of the hook's own objects, which hold the migrator's credentials.
check_migrated() {
  owner=$(psql -tAc "SELECT tableowner FROM pg_tables WHERE schemaname = 'encryption' AND tablename = '_prisma_migrations'")
  [ "$owner" = "encryption_migrator" ] || { echo "migration journal missing or not owned by the migrator (owner: '${owner}')" >&2; exit 1; }
  leftovers=$(kubectl -n "$NAMESPACE" get serviceaccount,secret,job -l app.kubernetes.io/component=migration -o name)
  [ -z "$leftovers" ] || { echo "the migration hook left objects behind: ${leftovers}" >&2; exit 1; }
}

# A first install, where the hook runs before the release has created anything: it can
# only succeed if the Job's ServiceAccount and Secret are hooks themselves.
echo "== install"
install migrator-1
check_migrated
echo "== helm test"
helm test "$RELEASE" --namespace "$NAMESPACE" --logs

# An upgrade that rotates the migrator's password: the hook runs before the release's
# objects are updated, so it would authenticate with the previous password if it read them.
echo "== upgrade (revision 2: rotated migrator password, rolling update with zero unavailable)"
psql -c "ALTER ROLE encryption_migrator PASSWORD 'migrator-2'"
install migrator-2 --set podLabels.smoke=revision-2
check_migrated
helm test "$RELEASE" --namespace "$NAMESPACE" --logs

echo "== result"
kubectl -n "$NAMESPACE" get deployment,pod,service,pdb -o wide
kubectl -n "$NAMESPACE" get events --field-selector type=Warning -o custom-columns=REASON:.reason,MESSAGE:.message | sed 1d | sort -u | sed 's/^/warning: /' || true
echo "OK: ${RELEASE} migrates, deploys, answers /health and upgrades in place (with a rotated migrator password) under the restricted Pod Security level"
