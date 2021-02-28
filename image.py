class Image:
    def __init__(self, release, cve_data):
        self.releases = [release]
        self.cve_data = cve_data
        self.sources = {}

    def add_release(self, release):
        self.releases.append(release)

    def add_source(self, source):
        self.sources[source] = True
