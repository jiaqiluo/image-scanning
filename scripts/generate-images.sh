#!/usr/bin/env bash

export GO111MODULE=on

## Rancher 2.5 images
git clone https://github.com/rancher/rancher && cd rancher && git fetch && git checkout release/v2.5
git clone https://github.com/rancher/system-charts && cd system-charts && git fetch && git checkout dev-v2.5 && cd ..
git clone https://github.com/rancher/charts && cd charts && git fetch && git checkout dev-v2.5 && cd ..

curl -sLf https://github.com/mikefarah/yq/releases/download/3.2.1/yq_linux_amd64 > yq && chmod +x yq

INDEX_PATH=charts/index.yaml
LATEST_TGZ_PATHS=$(./yq r $INDEX_PATH "entries.*.[0].urls[0]")
CHART_REPO_DIR=charts

# Extract the tarballs in charts, copied from rancher
for TGZ_PATH in $LATEST_TGZ_PATHS; do
  TGZ_REL_PATH=$CHART_REPO_DIR/$TGZ_PATH
  TGZ_EXTRACT_PATH=$(dirname $CHART_REPO_DIR/${TGZ_PATH##released/})
  if [[ $TGZ_PATH == *crd*.tgz ]]; then
    echo "Skipped CRD: $TGZ_REL_PATH"
  else
    echo "Extract: $TGZ_REL_PATH to $TGZ_EXTRACT_PATH"
    mkdir -p $TGZ_EXTRACT_PATH
    tar -xf $TGZ_REL_PATH -C $TGZ_EXTRACT_PATH
  fi
done

# Remove index to force building a virtual index like system charts
rm -f $INDEX_PATH $CHART_REPO_DIR/assets/index.yaml

mkdir bin
curl https://raw.githubusercontent.com/rancher/kontainer-driver-metadata/dev-v2.5/data/data.json -o bin/data.json

HOME=$(pwd)  REPO=rancher TAG=dev go run pkg/image/export/main.go system-charts charts/assets rancher/rancher:v2.5-head rancher/rancher-agent:v2.5-head
mv rancher-images-sources.txt ../rancher-images-sources-v2.5.txt
echo "Generated Rancher v2.5 images:"
cat ../rancher-images-sources-v2.5.txt
