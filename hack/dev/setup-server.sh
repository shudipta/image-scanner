#!/bin/bash
set -x

GOPATH=$(go env GOPATH)
REPO_ROOT="$GOPATH/src/github.com/soter/scanner"

pushd $REPO_ROOT

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

export SCANNER_NAMESPACE=scanner-dev
export KUBE_CA=$($ONESSL get kube-ca | $ONESSL base64)

while test $# -gt 0; do
    case "$1" in
        -n)
            shift
            if test $# -gt 0; then
                export SCANNER_NAMESPACE=$1
            else
                echo "no namespace specified"
                exit 1
            fi
            shift
            ;;
        --namespace*)
            shift
            if test $# -gt 0; then
                export SCANNER_NAMESPACE=$1
            else
                echo "no namespace specified"
                exit 1
            fi
            shift
            ;;
         *)
            echo $1
            exit 1
            ;;
    esac
done

#hack/dev/certgen.sh -n $SCANNER_NAMESPACE
#clair --config=$GOPATH/src/github.com/coreos/clair/config.sample.secure.notifier.yaml

# kubectl create ns $SCANNER_NAMESPACE
cat $REPO_ROOT/hack/dev/apiregistration.yaml | $ONESSL envsubst | kubectl apply -f -
cat $REPO_ROOT/hack/deploy/validating-webhook.yaml | $ONESSL envsubst | kubectl apply -f -

popd
