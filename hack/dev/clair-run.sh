#!/bin/bash
# set -eou pipefail

# https://stackoverflow.com/a/677212/244009
if [ -x "$(command -v onessl)" ]; then
    export ONESSL=onessl
else
    # ref: https://stackoverflow.com/a/27776822/244009
    case "$(uname -s)" in
        Darwin)
            curl -fsSL -o onessl https://github.com/kubepack/onessl/releases/download/0.3.0/onessl-darwin-amd64
            chmod +x onessl
            export ONESSL=./onessl
            ;;

        Linux)
            curl -fsSL -o onessl https://github.com/kubepack/onessl/releases/download/0.3.0/onessl-linux-amd64
            chmod +x onessl
            export ONESSL=./onessl
            ;;

        CYGWIN*|MINGW32*|MSYS*)
            curl -fsSL -o onessl.exe https://github.com/kubepack/onessl/releases/download/0.3.0/onessl-windows-amd64.exe
            chmod +x onessl.exe
            export ONESSL=./onessl.exe
            ;;
        *)
            echo 'other OS'
            ;;
    esac
fi

export SCANNER_NAMESPACE=kube-system
export SCANNER_DOCKER_REGISTRY=soter
export CLAIR_UNINSTALL=0

export SERVICE_SERVING_CERT_CA=$(cat pki/scanner/ca.crt | $ONESSL base64)
export NOTIFIER_CLIENT_CERT=$(cat pki/scanner/client.crt | $ONESSL base64)
export NOTIFIER_CLIENT_KEY=$(cat pki/scanner/client.key | $ONESSL base64)

export CLAIR_API_SERVING_CERT_CA=$(cat pki/clair/ca.crt | $ONESSL base64)
export CLAIR_API_SERVER_CERT=$(cat pki/clair/server.crt | $ONESSL base64)
export CLAIR_API_SERVER_KEY=$(cat pki/clair/server.key | $ONESSL base64)

while test $# -gt 0; do
    case "$1" in
        --uninstall)
            export CLAIR_UNINSTALL=1
            shift
            ;;
    esac
done

if [ "$CLAIR_UNINSTALL" -eq 1 ]; then
    echo "Uninstalling Clair ..."
    kubectl delete configmap -l app=clair -n $SCANNER_NAMESPACE
    (cat hack/deploy/clair/clair.yaml | $ONESSL envsubst | kubectl delete -f -) || true

    echo "Uninstalling Clair PostgreSQL ..."
    (cat hack/deploy/clair/postgresql.yaml | $ONESSL envsubst | kubectl delete -f -) || true

    echo "Successfully uninstalled Scanner!"
    exit 0
fi


# Running Clair PostgreSQL
echo
echo "Installing Clair PostgreSQL ..."
cat hack/dev/clair/postgresql.yaml | $ONESSL envsubst | kubectl apply -f -
echo "waiting until Clair PostgreSQL deployment is ready"
$ONESSL wait-until-ready deployment clair-postgresql --namespace $SCANNER_NAMESPACE || { echo "Clair PostgreSQL deployment failed to be ready"; exit 1; }

# Running clair
echo
echo "Installing Clair ..."
CONFIG_FOUND=1
kubectl get configmap clair-config -n $SCANNER_NAMESPACE > /dev/null 2>&1 || CONFIG_FOUND=0
if [ $CONFIG_FOUND -eq 0 ]; then
    config=`cat hack/dev/clair/config.yaml | $ONESSL envsubst`
    kubectl create configmap clair-config -n $SCANNER_NAMESPACE \
        --from-literal=config.yaml="${config}"
fi
kubectl label configmap clair-config app=clair -n $SCANNER_NAMESPACE --overwrite
cat hack/dev/clair/clair.yaml | $ONESSL envsubst | kubectl apply -f -

echo "waiting until Clair deployment is ready"
$ONESSL wait-until-ready deployment clair --namespace $SCANNER_NAMESPACE || { echo "Clair deployment failed to be ready"; exit 1; }
