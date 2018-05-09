#!/bin/bash


GOPATH=$(go env GOPATH)
REPO_ROOT="$GOPATH/src/github.com/soter/scanner"

pushd $REPO_ROOT

export SCANNER_NAMESPACE=scanner-dev

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

kubectl delete apiservice -l app=test-scanner
kubectl delete validatingwebhookconfiguration -l app=scanner

kubectl delete endpoints scanner-local-apiserver -n $SCANNER_NAMESPACE
kubectl delete svc scanner-local-apiserver -n $SCANNER_NAMESPACE

popd
