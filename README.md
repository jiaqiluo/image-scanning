# image-scanning

## Purpose
Image scanning repository aims to maintain lists of cves for multiple releases and to produce CVEs corresponding to those issue.

## How it works
### The following process is deployed as a github action and is on a cron job schedule that runs once a week:
1. Generate images for target releases by cloning Rancher and running image export script.
2. Download Trivy.
2. Scan each image using Trivy.
3. Save results to a csv for each release.
4. For each image with a CVE, check if it has an issue. If it exists, check if content needs to be updated and update if so. If not, create a new one. Ensure issues have correct labels.

### Publish CVEs
CVEs are published through Github pages using Jekyll. Users have two options: view CSV's directly or view CSV content as HTML tables at the repo's Github pages url.

## Manual steps
### Notes and state
Developers that are working on CVEs reported by this project can add notes to each CVE that will be preserved. 

### Checking if an image's CVEs have been resolved
Download trivy and run `trivy image -s HIGH,CRITICAL <image-name>`. Remove `-s HIGH,CRITICAL` if the CVE is lower in severity. An easy way to download trivy is to use the intall script:
`curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b $(pwd)`

### Adding releases
Steps for any new release that should be scanned must be added to the image scanning workflow: .github/workflows/scan-rancher-images.yaml.
If a release no longer needs to be scanned, it's steps should be removed from the image scanning workflow.
