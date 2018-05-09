#!/bin/bash
set -eou pipefail

apiServices=(v1alpha1.scanner v1alpha1.admission.scanner)

echo "checking kubeconfig context"
kubectl config current-context || { echo "Set a context (kubectl use-context <context>) out of the following:"; echo; kubectl config get-contexts; exit 1; }
echo ""

# http://redsymbol.net/articles/bash-exit-traps/
function cleanup {
    rm -rf $ONESSL pki
}
trap cleanup EXIT

# ref: https://github.com/appscodelabs/libbuild/blob/master/common/lib.sh#L55
inside_git_repo() {
    git rev-parse --is-inside-work-tree > /dev/null 2>&1
    inside_git=$?
    if [ "$inside_git" -ne 0 ]; then
        echo "Not inside a git repository"
        exit 1
    fi
}

detect_tag() {
    inside_git_repo

    # http://stackoverflow.com/a/1404862/3476121
    git_tag=$(git describe --exact-match --abbrev=0 2>/dev/null || echo '')

    commit_hash=$(git rev-parse --verify HEAD)
    git_branch=$(git rev-parse --abbrev-ref HEAD)
    commit_timestamp=$(git show -s --format=%ct)

    if [ "$git_tag" != '' ]; then
        TAG=$git_tag
        TAG_STRATEGY='git_tag'
    elif [ "$git_branch" != 'master' ] && [ "$git_branch" != 'HEAD' ] && [[ "$git_branch" != release-* ]]; then
        TAG=$git_branch
        TAG_STRATEGY='git_branch'
    else
        hash_ver=$(git describe --tags --always --dirty)
        TAG="${hash_ver}"
        TAG_STRATEGY='commit_hash'
    fi

    export TAG
    export TAG_STRATEGY
    export git_tag
    export git_branch
    export commit_hash
    export commit_timestamp
}

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

# ref: https://stackoverflow.com/a/7069755/244009
# ref: https://jonalmeida.com/posts/2013/05/26/different-ways-to-implement-flags-in-bash/
# ref: http://tldp.org/LDP/abs/html/comparison-ops.html

export SCANNER_NAMESPACE=kube-system
export SCANNER_SERVICE_ACCOUNT=scanner
export SCANNER_ENABLE_RBAC=true
export SCANNER_RUN_ON_MASTER=0
export SCANNER_POSTGRES_STORAGE_CLASS=standard
export SCANNER_ENABLE_VALIDATING_WEBHOOK=true
export SCANNER_DOCKER_REGISTRY=soter
export SCANNER_IMAGE_TAG=0.1.0
export SCANNER_IMAGE_PULL_SECRET=
export SCANNER_IMAGE_PULL_POLICY=IfNotPresent
export SCANNER_ENABLE_ANALYTICS=true
export SCANNER_UNINSTALL=0
export SCANNER_PURGE=0

export APPSCODE_ENV=${APPSCODE_ENV:-prod}
export SCRIPT_LOCATION="curl -fsSL https://raw.githubusercontent.com/soter/scanner/0.1.0/"
if [ "$APPSCODE_ENV" = "dev" ]; then
    detect_tag
    export SCRIPT_LOCATION="cat "
    export SCANNER_IMAGE_TAG=$TAG
    export SCANNER_IMAGE_PULL_POLICY=Always
fi

KUBE_APISERVER_VERSION=$(kubectl version -o=json | $ONESSL jsonpath '{.serverVersion.gitVersion}')
$ONESSL semver --check='>=1.9.0' $KUBE_APISERVER_VERSION || { echo "Scanner requires Kubernetes 1.9.0 or later version"; echo; exit 1; }

show_help() {
    echo "scanner.sh - install Docker image scanner"
    echo " "
    echo "scanner.sh [options]"
    echo " "
    echo "options:"
    echo "-h, --help                         show brief help"
    echo "-n, --namespace=NAMESPACE          specify namespace (default: kube-system)"
    echo "    --rbac                         create RBAC roles and bindings (default: true)"
    echo "    --postgres-storage-class       name of storage class used to store Clair PostgreSQL data (default: standard)"
    echo "    --docker-registry              docker registry used to pull scanner images (default: appscode)"
    echo "    --image-pull-secret            name of secret used to pull scanner operator images"
    echo "    --run-on-master                run scanner operator on master"
    echo "    --enable-validating-webhook    enable/disable validating webhooks for Scanner"
    echo "    --enable-analytics             send usage events to Google Analytics (default: true)"
    echo "    --uninstall                    uninstall scanner"
    echo "    --purge                        purges Clair installation"
}

while test $# -gt 0; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
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
            export SCANNER_NAMESPACE=`echo $1 | sed -e 's/^[^=]*=//g'`
            shift
            ;;
        --postgres-storage-class*)
            export SCANNER_POSTGRES_STORAGE_CLASS=`echo $1 | sed -e 's/^[^=]*=//g'`
            shift
            ;;
        --docker-registry*)
            export SCANNER_DOCKER_REGISTRY=`echo $1 | sed -e 's/^[^=]*=//g'`
            shift
            ;;
        --image-pull-secret*)
            secret=`echo $1 | sed -e 's/^[^=]*=//g'`
            export SCANNER_IMAGE_PULL_SECRET="name: '$secret'"
            shift
            ;;
        --enable-validating-webhook*)
            val=`echo $1 | sed -e 's/^[^=]*=//g'`
            if [ "$val" = "false" ]; then
                export SCANNER_ENABLE_VALIDATING_WEBHOOK=false
            fi
            shift
            ;;
        --enable-analytics*)
            val=`echo $1 | sed -e 's/^[^=]*=//g'`
            if [ "$val" = "false" ]; then
                export SCANNER_ENABLE_ANALYTICS=false
            fi
            shift
            ;;
        --rbac*)
            val=`echo $1 | sed -e 's/^[^=]*=//g'`
            if [ "$val" = "false" ]; then
                export SCANNER_SERVICE_ACCOUNT=default
                export SCANNER_ENABLE_RBAC=false
            fi
            shift
            ;;
        --run-on-master)
            export SCANNER_RUN_ON_MASTER=1
            shift
            ;;
        --uninstall)
            export SCANNER_UNINSTALL=1
            shift
            ;;
        --purge)
            export SCANNER_PURGE=1
            shift
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
done

if [ "$SCANNER_UNINSTALL" -eq 1 ]; then
    echo "Uninstalling Scanner ..."
    # delete webhooks and apiservices
    kubectl delete validatingwebhookconfiguration -l app=scanner
    kubectl delete mutatingwebhookconfiguration -l app=scanner
    kubectl delete apiservice -l app=scanner
    # delete scanner operator
    kubectl delete deployment -l app=scanner --namespace $SCANNER_NAMESPACE
    kubectl delete service -l app=scanner --namespace $SCANNER_NAMESPACE
    kubectl delete secret -l app=scanner --namespace $SCANNER_NAMESPACE
    # delete RBAC objects, if --rbac flag was used.
    kubectl delete serviceaccount -l app=scanner --namespace $SCANNER_NAMESPACE
    kubectl delete clusterrolebindings -l app=scanner
    kubectl delete clusterrole -l app=scanner
    kubectl delete rolebindings -l app=scanner --namespace $SCANNER_NAMESPACE
    kubectl delete role -l app=scanner --namespace $SCANNER_NAMESPACE

    echo "waiting for scanner operator pod to stop running"
    for (( ; ; )); do
       pods=($(kubectl get pods --all-namespaces -l app=scanner -o jsonpath='{range .items[*]}{.metadata.name} {end}'))
       total=${#pods[*]}
        if [ $total -eq 0 ] ; then
            break
        fi
       sleep 2
    done

    if [ "$SCANNER_PURGE" -eq 1 ]; then
        echo "waiting 5 seconds ..."
        sleep 5;

        echo "Uninstalling Clair ..."
        kubectl delete secret -l app=clair -n $SCANNER_NAMESPACE
        (${SCRIPT_LOCATION}hack/deploy/clair/clair.yaml | $ONESSL envsubst | kubectl delete -f -) || true

        echo "Uninstalling Clair PostgreSQL ..."
        (${SCRIPT_LOCATION}hack/deploy/clair/postgresql.yaml | $ONESSL envsubst | kubectl delete -f -) || true
    fi

    echo
    echo "Successfully uninstalled Scanner!"
    exit 0
fi

echo "checking whether extended apiserver feature is enabled"
$ONESSL has-keys configmap --namespace=kube-system --keys=requestheader-client-ca-file extension-apiserver-authentication || { echo "Set --requestheader-client-ca-file flag on Kubernetes apiserver"; exit 1; }
echo ""

export KUBE_CA=
if [ "$SCANNER_ENABLE_VALIDATING_WEBHOOK" = true ]; then
    $ONESSL get kube-ca >/dev/null 2>&1 || { echo "Admission webhooks can't be used when kube apiserver is accesible without verifying its TLS certificate (insecure-skip-tls-verify : true)."; echo; exit 1; }
    export KUBE_CA=$($ONESSL get kube-ca | $ONESSL base64)
fi

env | sort | grep SCANNER*
echo ""

echo "creating necessary certificate-key pairs"

# create necessary TLS certificates:
# - a local CA key and cert
# - a webhook server key and cert signed by the local CA
$ONESSL create ca-cert --cert-dir=pki/scanner
$ONESSL create server-cert server --cert-dir=pki/scanner --domains=scanner.${SCANNER_NAMESPACE}.svc

# In the clair notifier part, server=scanner-server, client=clair
# create necessary TLS certificates:
# - a client key and cert signed by the above local CA for clair notifier
$ONESSL create client-cert client --cert-dir=pki/scanner

# In the clair api part: server=clair, client=scanner-server
# create necessary TLS certificates:
# - a CA key and cert for clair api
# - a server key and cert signed by this CA for clair api
# - a client key and cert signed by this CA for clair api
$ONESSL create ca-cert --cert-dir=pki/clair
$ONESSL create server-cert server --cert-dir=pki/clair --domains=clairsvc.${SCANNER_NAMESPACE}.svc
$ONESSL create client-cert client --cert-dir=pki/clair

export SERVICE_SERVING_CERT_CA=$(cat pki/scanner/ca.crt | $ONESSL base64)
export TLS_SERVING_CERT=$(cat pki/scanner/server.crt | $ONESSL base64)
export TLS_SERVING_KEY=$(cat pki/scanner/server.key | $ONESSL base64)
export NOTIFIER_CLIENT_CERT=$(cat pki/scanner/client.crt | $ONESSL base64)
export NOTIFIER_CLIENT_KEY=$(cat pki/scanner/client.key | $ONESSL base64)

export CLAIR_API_SERVING_CERT_CA=$(cat pki/clair/ca.crt | $ONESSL base64)
export CLAIR_API_SERVER_CERT=$(cat pki/clair/server.crt | $ONESSL base64)
export CLAIR_API_SERVER_KEY=$(cat pki/clair/server.key | $ONESSL base64)
export CLAIR_API_CLIENT_CERT=$(cat pki/clair/client.crt | $ONESSL base64)
export CLAIR_API_CLIENT_KEY=$(cat pki/clair/client.key | $ONESSL base64)

# Running Clair PostgreSQL
echo
echo "Installing Clair PostgreSQL ..."
${SCRIPT_LOCATION}hack/deploy/clair/postgresql.yaml | $ONESSL envsubst | kubectl apply -f -
echo "waiting until Clair PostgreSQL deployment is ready"
$ONESSL wait-until-ready deployment clair-postgresql --namespace $SCANNER_NAMESPACE || { echo "Clair PostgreSQL deployment failed to be ready"; exit 1; }

# Running clair
echo
echo "Installing Clair ..."
CONFIG_FOUND=1
kubectl get secret clair-config -n $SCANNER_NAMESPACE > /dev/null 2>&1 || CONFIG_FOUND=0
if [ $CONFIG_FOUND -eq 0 ]; then
    config=`${SCRIPT_LOCATION}hack/deploy/clair/config.yaml | $ONESSL envsubst`
    kubectl create secret generic clair-config -n $SCANNER_NAMESPACE \
        --from-literal=config.yaml="${config}"
fi
kubectl label secret clair-config app=clair -n $SCANNER_NAMESPACE --overwrite
${SCRIPT_LOCATION}hack/deploy/clair/clair.yaml | $ONESSL envsubst | kubectl apply -f -

echo "waiting until Clair deployment is ready"
$ONESSL wait-until-ready deployment clair --namespace $SCANNER_NAMESPACE || { echo "Clair deployment failed to be ready"; exit 1; }

# Running Scanner
${SCRIPT_LOCATION}hack/deploy/deployment.yaml | $ONESSL envsubst | kubectl apply -f -

if [ "$SCANNER_ENABLE_RBAC" = true ]; then
    kubectl create serviceaccount $SCANNER_SERVICE_ACCOUNT --namespace $SCANNER_NAMESPACE
    kubectl label serviceaccount $SCANNER_SERVICE_ACCOUNT app=scanner --namespace $SCANNER_NAMESPACE
    ${SCRIPT_LOCATION}hack/deploy/rbac-list.yaml | $ONESSL envsubst | kubectl auth reconcile -f -
fi

if [ "$SCANNER_RUN_ON_MASTER" -eq 1 ]; then
    kubectl patch deploy scanner -n $SCANNER_NAMESPACE \
      --patch="$(${SCRIPT_LOCATION}hack/deploy/run-on-master.yaml)"
fi

if [ "$SCANNER_ENABLE_VALIDATING_WEBHOOK" = true ]; then
    ${SCRIPT_LOCATION}hack/deploy/validating-webhook.yaml | $ONESSL envsubst | kubectl apply -f -
fi

echo
echo "waiting until Scanner deployment is ready"
$ONESSL wait-until-ready deployment scanner --namespace $SCANNER_NAMESPACE || { echo "Scanner deployment failed to be ready"; exit 1; }

echo "waiting until Scanner apiservice is available"
for api in "${apiServices[@]}"; do
    $ONESSL wait-until-ready apiservice "${api}.soter.ac" || { echo "Scanner apiservice ${api}.soter.ac failed to be ready"; exit 1; }
done

echo
echo "Successfully installed Scanner in $SCANNER_NAMESPACE namespace!"
