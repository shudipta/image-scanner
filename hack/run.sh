#!/usr/bin/env bash
#set -xe
GOPATH=$(go env GOPATH)
PACKAGE_NAME=image-scanner
REPO_ROOT="$GOPATH/src/github.com/shudipta/$PACKAGE_NAME"

pushd $REPO_ROOT

kubectl create secret generic clairsecret --from-file=./hack/deploy/config.yaml
kubectl create -f ./hack/deploy/clair-kubernetes.yaml

popd
