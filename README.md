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
CVEs for both releases are published through Github pages using Jekyll. Eventually this repository will be public, at which point users have two options: view CSV's directly or view CSV content
as HTML tables at the repo's Github pages url.

## Issues
One issue will be created for each image that has a CVE. This issue will contains a table of packages that have CVEs linked to them. Each row contains info such as package name, the cve that is effecting it,
the CVE's title, URL, etc.. Every image will posses the "cve-report" label. If the image has any CVEs that are of "CRITICAL" severity, the issue will possess the "critical-cves" label.

## Manual steps
### Notes and state
Developers that are working on CVEs reported by this project can add notes to each CVE that will be preserved. In the future they will be able to set an issue's state to "ignore" to indicate it is a false-positive
or something similar. Any ignored CVE's should contain a justification for the state in the "notes" column.

### Checking if an image's CVEs have been resolved
Download trivy and run `trivy image -s HIGH,CRITICAL <image-name>`. Remove `-s HIGH,CRITICAL` if the CVE is lower in severity. An easy way to download trivy is to use the intall script:
`curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b $(pwd)`

### Adding releases
Steps for any new release that should be scanned must be added to the image scanning workflow: .github/workflows/scan-rancher-images.yaml.
If a release no longer needs to be scanned, it's steps should be removed from the image scanning workflow.

## TODO
* Label each image issue with what project(s) contain the image and which releases contain the project.
* Add logic to close issues that no longer contain CVE's
* Windows images
* Do not include CVE's with state "ignore" in all release in issues
* Highlight "ignore" CVE's in HTML to indicate they can be differet
* Label mirrored images as such

