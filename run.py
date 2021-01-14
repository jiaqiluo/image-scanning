import json
import subprocess
import csv
import array
import os

with open(os.getcwd() + "/rancher-images.txt") as images_file:
    images = images_file.read()
images_list = images.split()
print(len(images_list))
# images_list = ["rancher/rancher:v2.5.4", "rancher/rancher:v2.5.3"]
vulnerabilities = []
readable_vulnerabilities = []
skipped_images = []
mirrored_images = {}

with open('mirrored_list.txt', 'r', newline='') as mirrorfile:
    for line in mirrorfile:
        if line == "\n":
            print('skip')
            continue
        print(line)
        print(line.split(" "))
        a = line.split(" ")
        mirrored_image = a[1] + ":" + a[2]
        mirrored_images[mirrored_image] = True
with open('cves.csv', 'a', newline='') as csvfile:
    header = ['image', 'package_name', 'type', 'vulnerability_id', 'severity', 'url', 'patched_version', 'mirrored']
    writer = csv.DictWriter(csvfile, fieldnames=header)

    writer.writeheader()
    for image in images_list:
        # print(image)
        output = subprocess.getoutput("trivy image -s HIGH,CRITICAL -f json -t 3m0s -o output.txt " + image)
        with open("output.txt") as scan_output_file:
            scan_output = scan_output_file.read()
        print(scan_output)
        if scan_output == "null":
            print("continue")
            skipped_images.append(image)
            continue
        obj = json.loads(scan_output)
        print(obj)
        vulnerabilities = obj[0]["Vulnerabilities"]
        base_type = obj[0]["Type"]
        # url = vulnerabilities["PrimaryURL"]
        unique_vulnerabilities = {}
        print(vulnerabilities)
        if vulnerabilities is None:
            continue
        for vulnerability in vulnerabilities:
            id = vulnerability["VulnerabilityID"]
            url = vulnerability["PrimaryURL"]
            fixed_version = vulnerability.get("FixedVersion", "")
            if unique_vulnerabilities.get(id, None) is not None:
                continue
            unique_vulnerabilities[id] = "PrimaryURL: " + url + ", FixedVersion: " + fixed_version
            writer.writerow({'image': image, 'package_name': vulnerability['PkgName'], 'type': base_type, 'vulnerability_id': id, 'severity': vulnerability['Severity'], 'url': url, 'patched_version': fixed_version})
            # print(image, vulnerability["VulnerabilityID"], vulnerability["PrimaryURL"])
        print(unique_vulnerabilities)
        # for vulnerability in unique_vulnerabilities:
        #     print(image, vulnerability, unique_vulnerabilities[vulnerability])
        if output is not None:
            print(dir(output))

    with open("skipped_images.txt", 'w', newline='') as skipped_output_file:
        skipped_output_file.write("\n".join(skipped_images))

    with open('mirrored_list.txt', 'r', newline='') as mirrorfile:
        for line in mirrorfile:
            mirrored_image = line.split(" ")[1]

