#!/bin/bash
set -eou pipefail

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

rm -rf $ONESSL ca.crt ca.key server.crt server.key client@client.crt client@client.key
pushd $GOPATH/src/github.com/soter/scanner/clair-cert
rm -rf $ONESSL ca.crt ca.key server.crt server.key client@soter.ac.crt client@soter.ac.key
popd

echo "creating necessary certificate-key pairs"

# create necessary TLS certificates:
# - a local CA key and cert
# - a webhook server key and cert signed by the local CA
export SCANNER_NAMESPACE=kube-system
$ONESSL create ca-cert
$ONESSL create server-cert server --domains=scanner.$SCANNER_NAMESPACE.svc

# In the clair notifier part, server=scanner-apiserver, client=clair
# create necessary TLS certificates:
# - a client key and cert signed by the above local CA for clair notifier
$ONESSL create client-cert client --organization=clair

# In the clair api part: server=clair, client=scanner-apiserver
# create necessary TLS certificates:
# - a CA key and cert for clair api
# - a server key and cert signed by this CA for clair api
# - a client key and cert signed by this CA for clair api
$ONESSL create ca-cert --cert-dir=clair-cert/
$ONESSL create server-cert server --cert-dir=clair-cert/ --domains=clairsvc.default.svc --ips="192.168.99.100,0.0.0.0"
$ONESSL create client-cert client --cert-dir=clair-cert/ --organization=soter.ac

