# image-scanner
Check image vulnerabilities using [Clair](https;//github.com/coreos/clair)

## Requirements to Run
[minikube](https;//github.com/coreos/clair)


## Run
From the project's root we have to run the followings commands
- `kubectl create secret generic clairsecret --from-file=./hack/deploy/config.yaml`
- `kubectl create -f ./hack/deploy/clair-kubernetes.yaml`
- `go run main.go --image=<image_name>`
    for public image.

    If the image is private, then we have to add flags for credentials.
    
    e.g. `go run main.go --image=<image_name> --user=<username> --pass=<password>`
    
