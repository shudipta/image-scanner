#!/usr/bin/env bash
#set -xe
GOPATH=$(go env GOPATH)
PACKAGE_NAME=image-scanner
REPO_ROOT="$GOPATH/src/github.com/shudipta/$PACKAGE_NAME"

pushd $REPO_ROOT

kubectl delete secret clairsecret
kubectl delete -f ./hack/deploy/clair-kubernetes.yaml

popd
