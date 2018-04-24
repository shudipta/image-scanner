#!/usr/bin/env bash
set -eou pipefail

while test $# -gt 0; do
    case "$1" in
        --uninstall)
            kubectl delete secret -l app=clair
            kubectl delete service -l app=clair
            kubectl delete service -l app=postgres
            kubectl delete rc -l app=clair
            kubectl delete rc -l app=postgres
            exit 1
            ;;
    esac
done

# https://stackoverflow.com/a/677212/244009
if [ -x "$(command -v onessl)" ]; then
    export ONESSL=onessl
else
    # ref: https://stackoverflow.com/a/27776822/244009
    case "$(uname -s)" in
        Darwin)
            curl -fsSL -o onessl https://github.com/kubepack/onessl/releases/download/0.1.0/onessl-darwin-amd64
            chmod +x onessl
            export ONESSL=./onessl
            ;;

        Linux)
            curl -fsSL -o onessl https://github.com/kubepack/onessl/releases/download/0.1.0/onessl-linux-amd64
            chmod +x onessl
            export ONESSL=./onessl
            ;;

        CYGWIN*|MINGW32*|MSYS*)
            curl -fsSL -o onessl.exe https://github.com/kubepack/onessl/releases/download/0.1.0/onessl-windows-amd64.exe
            chmod +x onessl.exe
            export ONESSL=./onessl.exe
            ;;
        *)
            echo 'other OS'
            ;;
    esac
fi

export SCANNER_NAMESPACE=kube-system

export APPSCODE_ENV=${APPSCODE_ENV:-prod}
export SCRIPT_LOCATION="curl -fsSL https://raw.githubusercontent.com/soter/scanner/master/"
if [ "$APPSCODE_ENV" = "dev" ]; then
    export SCRIPT_LOCATION="cat "
fi

echo "running clair"

# Exporting certificates for clair notifier.
export CLAIR_NOTIFIER_SERVING_CERT_CA=$(cat ca.crt | $ONESSL base64)
export CLAIR_NOTIFIER_CLIENT_CERT=$(cat client@clair.crt | $ONESSL base64)
export CLAIR_NOTIFIER_CLIENT_KEY=$(cat client@clair.key | $ONESSL base64)

# Exporting certificates for clair api.
export CLAIR_API_SERVING_CERT_CA=$(cat clair-cert/ca.crt | $ONESSL base64)
export CLAIR_API_SERVER_CERT=$(cat clair-cert/server.crt | $ONESSL base64)
export CLAIR_API_SERVER_KEY=$(cat clair-cert/server.key | $ONESSL base64)

# Running clair
kubectl create secret generic clairsecret --from-file=docs/examples/clair/config.yaml
kubectl label secret clairsecret app=clair
${SCRIPT_LOCATION}docs/examples/clair/clair-kubernetes.yaml | $ONESSL envsubst | kubectl apply -f -
