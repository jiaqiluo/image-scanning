import json
import subprocess
import csv
import array
import os
import sys

if len(sys.argv) != 3:
    print("Must pass two arguments, images text file name and name of csv file containing cves.")
    sys.exit(1)

cves_csv_filenames = sys.argv[1].split(",")
images_text_filenames = sys.argv[2].split(",")

mirrored_images = {}

with open('mirrored_list.txt', 'r', newline='') as mirrorfile:
    for line in mirrorfile:
        if line == "\n":
            continue
        a = line.split(" ")
        mirrored_image = a[1] + ":" + a[2]
        mirrored_images[mirrored_image] = True

for index, cves_csv_filename in enumerate(cves_csv_filenames):
    images_text_filename = images_text_filenames[index]
    with open(os.getcwd() + "/" + images_text_filename) as images_file:
        images = images_file.read()

    images_list = images.split()
    vulnerabilities = []
    skipped_images = []
    image_info = {}
    cve_memory = {}
    with open(cves_csv_filename, 'r', newline='') as csvfile:
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

    with open(cves_csv_filename, 'w', newline='') as csvfile:
        header = ['image', 'package_name', 'type', 'vulnerability_id', 'severity', 'url', 'patched_version', 'mirrored', 'state', 'notes']
        writer = csv.DictWriter(csvfile, fieldnames=header)

        writer.writeheader()
        for image in images_list:
            if cve_memory.get(image, None) is not None:
                obj = cve_memory[image]
            else:
                output = subprocess.getoutput("./trivy image -s HIGH,CRITICAL -f json -t 3m0s -o output.txt " + image)
                scan_output = ""
                with open("output.txt") as scan_output_file:
                    scan_output = scan_output_file.read()
                if scan_output is None or scan_output == "null" or scan_output == "":
                    skipped_images.append(image)
                    continue
                obj = json.loads(scan_output)
                cve_memory[image] = obj
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

