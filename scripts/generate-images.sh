#!/usr/bin/env bash

export GO111MODULE=on


function extract_charts() {
  for TGZ_PATH in $1; do
    TGZ_REL_PATH=$2/$TGZ_PATH
    TGZ_EXTRACT_PATH=$(dirname $2/${TGZ_PATH##released/})
    if [[ $TGZ_PATH == *crd*.tgz ]]; then
      echo "Skipped CRD: $TGZ_REL_PATH"
    else
      echo "Extract: $TGZ_REL_PATH to $TGZ_EXTRACT_PATH"
      mkdir -p $TGZ_EXTRACT_PATH
      tar -xf $TGZ_REL_PATH -C $TGZ_EXTRACT_PATH
    fi
  done
}

curl -sLf https://github.com/mikefarah/yq/releases/download/3.2.1/yq_linux_amd64 > yq && chmod +x yq

INDEX_PATH=charts/index.yaml
CHART_REPO_DIR=charts

## Rancher 2.6 images
git clone https://github.com/rancher/rancher && cd rancher && git fetch && git checkout origin/master
git clone https://github.com/rancher/system-charts && cd system-charts && git fetch && git checkout origin/dev-v2.6 && cd ..
git clone https://github.com/rancher/charts && cd charts && git fetch && git checkout origin/dev-v2.6 && cd ..

LATEST_TGZ_PATHS=$(./../yq r $INDEX_PATH "entries.*.[0].urls[0]")

# Extract the tarballs in charts, copied from rancher
extract_charts "$LATEST_TGZ_PATHS" $CHART_REPO_DIR

# Remove index to force building a virtual index like system charts
rm -f $INDEX_PATH $CHART_REPO_DIR/assets/index.yaml

mkdir bin
curl https://raw.githubusercontent.com/rancher/kontainer-driver-metadata/dev-v2.6/data/data.json -o bin/data.json

HOME=$(pwd)  REPO=rancher TAG=dev go run pkg/image/export/main.go system-charts charts/assets rancher/rancher:v2.6-head rancher/rancher-agent:v2.6-head
mv rancher-images-sources.txt ../rancher-images-sources-v2.6.txt
echo "Generated Rancher v2.6 images:"
cat ../rancher-images-sources-v2.6.txt

