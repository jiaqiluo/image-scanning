import csv
import json
import os
import subprocess
import sys
import time

import github
import github.Label

from image import Image

# common issue labels
cve_report_label = "cve-report"
critical_cves_label = "critical-cves"

# TODO: remove this once it is no longer needed
disable_issues = False

# used to create labels with a variety of colors
color_counter = 0


def run():
    if len(sys.argv) != 6:
        print("Must pass five arguments: images text file names, names of csv files, release names, issue repository,"
              "and github token.")
        sys.exit(1)

    cves_csv_filenames = sys.argv[1].split(",")
    images_text_filenames = sys.argv[2].split(",")
    release_names = sys.argv[3].split(",")
    repository = sys.argv[4]
    token = sys.argv[5]

    can_ignore = {}
    cve_memory = {}

    for index, cves_csv_filename in enumerate(cves_csv_filenames):
        images_text_filename = images_text_filenames[index]
        release = release_names[index]
        with open(os.getcwd() + "/" + images_text_filename) as images_file:
            images = images_file.read()

        images_sources_list = images.split("\n")
        skipped_images = []
        image_info = {}

        # get current notes and state of CVES
        with open(cves_csv_filename, 'r', newline='') as csvfile:
            csv_reader = csv.DictReader(csvfile)
            record_notes_and_state(csv_reader, image_info, can_ignore)

        # write updated CVE info
        with open(cves_csv_filename, 'w', newline='') as csvfile:
            headers = ['image', 'package_name', 'type', 'vulnerability_id', 'severity', 'url', 'patched_version', 'mirrored', 'state', 'notes']
            writer = csv.DictWriter(csvfile, fieldnames=headers)

            writer.writeheader()
            write_cve_csv(writer, images_sources_list, cve_memory, skipped_images, release, image_info)

            with open("skipped_images.txt", 'w', newline='') as skipped_output_file:
                skipped_output_file.write("\n".join(skipped_images))

    # TODO: remove this once all issues can be generated
    if disable_issues:
        return

    # create/update issues for images with CVEs
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
        vulnerabilities = info.cve_data[0]["Vulnerabilities"]
        body, critical = generate_issue_body(images, vulnerabilities, can_ignore)

        current_source_labels = get_current_source_labels(rs)
        issue_number = image_issue_number.get(image, None)

        # build list of issue labels
        source_labels = generate_source_labels(rs, current_source_labels, info.sources)
        release_labels = generate_release_labels(rs, current_source_labels, info.releases)
        all_labels = [cve_report_label] + source_labels + release_labels
        if critical:
            all_labels.append(critical_cves_label)

        # manage CVE issues
        if issue_number is None:
            if body != "":
                # issue for image does not exist, create one
                print("creating CVE Report issue for " + image)
                rs.create_issue(title="[CVE Report]: " + image, body=body, labels=all_labels)
        else:
            # issue already exists, update current issue
            current_issue = rs.get_issue(issue_number)
            has_update = False
            if current_issue.body != body:
                if body == "":
                    current_issue.edit(state="closed")
                else:
                    current_issue.edit(body=body)
                has_update = True
            if set(map(lambda x: x.name, current_issue.get_labels())) != set(all_labels):
                current_issue.set_labels(*all_labels)
                has_update = True
            if has_update:
                print("updating CVE Report issue for " + image)
                current_issue.update()

        # issue creation faces additional rate limiting that can be hit even if below
        # user limit. It is necessary to wait in between requests.
        time.sleep(20)

    mark_as_can_close(rs, cve_memory, image_issue_number)


def parse_image_and_sources(image_and_sources):
    parts = image_and_sources.split()
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[1]


def record_notes_and_state(csv_reader, image_info, can_ignore):
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


def write_cve_csv(writer, images_sources_list, cve_memory, skipped_images, release, image_info):
    for image_and_sources in images_sources_list:
        if image_and_sources == "":
            continue
        image, sources = parse_image_and_sources(image_and_sources)
        if cve_memory.get(image, None) is not None:
            cve_memory[image].add_release(release)
            obj = cve_memory[image].cve_data
        else:
            # TODO: check for errors returned by trivy and properly update skipped images based on result
            output = subprocess.getoutput("./trivy image -s HIGH,CRITICAL -f json -t 3m0s -o output.txt " + image)
            with open("output.txt") as scan_output_file:
                scan_output = scan_output_file.read()
            if scan_output is None or scan_output == "null" or scan_output == "":
                skipped_images.append(image)
                continue
            obj = json.loads(scan_output)
            cve_memory[image] = Image(release, obj)

        for source in sources.split(","):
            cve_memory[image].add_source(source)

        vulnerabilities = obj[0]["Vulnerabilities"]
        base_type = obj[0]["Type"]
        if vulnerabilities is None:
            continue
        for vulnerability in vulnerabilities:
            write_cve(writer, vulnerability, image, image_info, base_type)


def write_cve(writer, vulnerability, image, image_info, base_type):
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


def generate_issue_body(image, vulnerabilities, can_ignore):
    if vulnerabilities is None or len(vulnerabilities) == 0:
        return "", False

    body = "|Vulnerability ID|Title|Package Name|Fixed Version|Severity|URL|\n|---|---|---|---|---|---|"
    critical = False
    for vulnerability in vulnerabilities:
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
    return body, critical


def has_critical_cve_label(gh_labels):
    for label in gh_labels:
        if label.name == critical_cves_label:
            return True
    return False


def get_current_source_labels(rs):
    source_labels = {}
    labels = rs.get_labels()

    for label in labels:
        if label.name.startswith("cve/"):
            source_labels[label.name] = True
    return source_labels


def create_missing_labels(rs, current_labels, check_labels):
    for label in check_labels:
        if current_labels.get(label, None):
            continue
        rs.create_label(
            name=label,
            description="automatically created label indicating where image is used",
            color=random_color()
        )


def generate_source_labels(rs, current_labels, sources):
    labels = []
    for source, hasSource in sources.items():
        if not hasSource:
            continue
        labels.append("cve/" + source.split(":")[0])
    create_missing_labels(rs, current_labels, labels)
    return labels


def generate_release_labels(rs, current_labels, releases):
    labels = []
    for release in releases:
        labels.append("cve/" + release)
    create_missing_labels(rs, current_labels, labels)
    return labels


def random_color():
    global color_counter
    colors = ("4287f5", "3ef08e", "ae35f0", "a4a1c2", "ffb300", "ff00cc")
    color_counter = (color_counter + 1) % len(colors)
    return colors[color_counter]


def mark_as_can_close(rs, cve_memory, image_issues):
    can_close_label = "cve/can-close"
    has_can_close_label = False
    labels = rs.get_labels()
    for label in labels:
        if label.name == can_close_label:
            has_can_close_label = True
    if not has_can_close_label:
        rs.create_label(
            name=can_close_label,
            description="this issue has been marked by automation as closeable",
            color=random_color()
        )
    for image, issue_number in image_issues.items():
        if cve_memory.get(image, None) is not None:
            continue
        current_issue = rs.get_issue(issue_number)
        current_issue.add_to_labels(can_close_label)


run()
