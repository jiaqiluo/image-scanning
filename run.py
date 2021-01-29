import json
import subprocess
import csv
import os
import sys
import github
import github.Label
import time

cve_report_label = "cve-report"
critical_cves_label = "critical-cves"


def run():
    if len(sys.argv) != 5:
        print("Must pass four arguments, images text file name, name of csv file, issue repository, and github token.")
        sys.exit(1)

    cves_csv_filenames = sys.argv[1].split(",")
    images_text_filenames = sys.argv[2].split(",")
    repository = sys.argv[3]
    token = sys.argv[4]

    mirrored_images = {}

    with open('mirrored_list.txt', 'r', newline='') as mirrorfile:
        for line in mirrorfile:
            if line == "\n":
                continue
            a = line.split(" ")
            mirrored_image = a[1] + ":" + a[2]
            mirrored_images[mirrored_image] = True

    can_ignore = {}
    cve_memory = {}

    for index, cves_csv_filename in enumerate(cves_csv_filenames):
        images_text_filename = images_text_filenames[index]
        with open(os.getcwd() + "/" + images_text_filename) as images_file:
            images = images_file.read()

        images_list = images.split()
        vulnerabilities = []
        skipped_images = []
        image_info = {}
        # cve_memory = {}
        with open(cves_csv_filename, 'r', newline='') as csvfile:
            csv_reader = csv.DictReader(csvfile)
            for line in csv_reader:
                image = line.get("image")
                package_name = line.get("package_name")
                vulnerability_id = line.get("vulnerability_id")
                key = image + "-" + package_name + "-" + vulnerability_id
                notes = line.get("notes", "")
                state = line.get("state", "triage")
                if state == "ignore":
                    if can_ignore.get(key, None) is None:
                        can_ignore[key] = True
                else:
                    can_ignore[key] = False
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

    gh = github.Github(login_or_token=token)
    rs = gh.get_repo(repository)
    image_issue_number = {}
    upstream_issues = rs.get_issues(state="open", labels=[cve_report_label])
    for i in upstream_issues:
        cve_prefix = "[CVE Report]: "
        if not i.title.startswith("[CVE Report]:"):
            continue

        image_name = i.title[len(cve_prefix):]
        image_issue_number[image_name] = i.number

    for image, info in cve_memory.items():
        body = "|Vulnerability ID|Title|Package Name|Fixed Version|Severity|URL|\n|---|---|---|---|---|---|"
        vulnerabilities = info[0]["Vulnerabilities"]
        critical = False
        if vulnerabilities is None:
            print(image + " has no vulnerabilities")
            continue
        for vulnerability in info[0]["Vulnerabilities"]:
            vulnerability_id = vulnerability["VulnerabilityID"]
            package_name = vulnerability['PkgName']
            title = vulnerability.get("Title", "")
            primary_url = vulnerability.get("PrimaryURL", "")
            key = image + "-" + package_name + "-" + vulnerability_id
            if can_ignore.get(key, False):
                continue
            fixed_version = vulnerability.get("FixedVersion", "")
            severity = vulnerability.get("Severity", "")
            if severity == "CRITICAL":
                critical = True
            body = body + "\n|" + vulnerability_id + "|" + title + "|" + package_name + "|" + fixed_version + "|" + \
                severity + "|" + primary_url + "|"
        issue_number = image_issue_number.get(image, None)
        if issue_number is None:
            labels = [cve_report_label]
            if critical:
                labels.append(critical_cves_label)
            print("creating CVE Report issue for " + image)
            rs.create_issue(title="[CVE Report]: " + image, body=body, labels=labels)
        else:
            current_issue = rs.get_issue(issue_number)
            has_update = False
            if current_issue.body != body:
                current_issue.edit(body=body)
                has_update = True
            if has_critical_cve_label(current_issue.labels) != critical:
                if critical:
                    current_issue.add_to_labels(critical_cves_label)
                else:
                    current_issue.remove_from_labels(critical_cves_label)
                has_update = True
            if has_update:
                print("updating CVE Report issue for " + image)
                current_issue.update()
        # issue creation faces additional rate limiting that can be hit even if below
        # user limit. It is necessary to wait in between requests.
        time.sleep(20)


def has_critical_cve_label(gh_labels):
    for label in gh_labels:
        if label.name == critical_cves_label:
            return True
    return False


run()
