import json
import subprocess
import csv
import array
import os

with open(os.getcwd() + "/rancher-images.txt") as images_file:
    images = images_file.read()

images_list = images.split()
vulnerabilities = []
skipped_images = []
mirrored_images = {}
image_info = {}

with open('mirrored_list.txt', 'r', newline='') as mirrorfile:
    for line in mirrorfile:
        if line == "\n":
            continue
        a = line.split(" ")
        mirrored_image = a[1] + ":" + a[2]
        mirrored_images[mirrored_image] = True

with open('cves.csv', 'r', newline='') as csvfile:
    csv_reader = csv.DictReader(csvfile)
    for line in csv_reader:
        image = line.get("image")
        package_name = line.get("package_name")
        vulnerability_id = line.get("vulnerability_id")
        key = image + "-" + package_name + "-" + vulnerability_id
        notes = line.get("notes", "")
        state = line.get("state", "triage")
        image_info[key] = {
                "notes": notes,
                "state": state,
        }

with open('cves.csv', 'w', newline='') as csvfile:
    header = ['image', 'package_name', 'type', 'vulnerability_id', 'severity', 'url', 'patched_version', 'mirrored', 'state', 'notes']
    writer = csv.DictWriter(csvfile, fieldnames=header)

    writer.writeheader()
    for image in images_list:
        output = subprocess.getoutput("./trivy image -s HIGH,CRITICAL -f json -t 3m0s -o output.txt " + image)
        scan_output = ""
        with open("output.txt") as scan_output_file:
            scan_output = scan_output_file.read()
        if scan_output is None or scan_output == "null" or scan_output == "":
            skipped_images.append(image)
            continue
        obj = json.loads(scan_output)
        vulnerabilities = obj[0]["Vulnerabilities"]
        base_type = obj[0]["Type"]
        # unique_vulnerabilities = {}
        if vulnerabilities is None:
            continue
        for vulnerability in vulnerabilities:
            vulnerability_id = vulnerability["VulnerabilityID"]
            package_name = vulnerability['PkgName']
            url = vulnerability["PrimaryURL"]
            fixed_version = vulnerability.get("FixedVersion", "")
            key = image + "-" + package_name + "-" + vulnerability_id
            image_notes = image_info.get(key, {})
            writer.writerow(
                    {
                        'image': image,
                        'package_name': package_name,
                        'type': base_type,
                        'vulnerability_id': vulnerability_id,
                        'severity': vulnerability['Severity'],
                        'url': url,
                        'patched_version': fixed_version,
                        'state': image_notes.get("state", "triaged"),
                        'notes': image_notes.get("notes", ""),
                    })

    with open("skipped_images.txt", 'w', newline='') as skipped_output_file:
        skipped_output_file.write("\n".join(skipped_images))

    with open('mirrored_list.txt', 'r', newline='') as mirrorfile:
        for line in mirrorfile:
            parts = line.split(" ")
            if len(parts) < 2:
                mirrored_image = parts[0]
                continue
            mirrored_image = parts[1]

