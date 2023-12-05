from collections import defaultdict


severity_map = {
    0: "System info",
    1: "Info",
    2: "Finding",
    3: "Vulnerability",
}


class Report(object):
    def __init__(self, filename):
        self.filename = filename
        self.result = defaultdict(lambda: [])

    def report(self, target, severity, description):
        self.result[target].append(
            {
                "severity": severity_map[severity],
                "description": description,
            }
        )

    def write(self):
        if not self.filename:
            return

        import json

        json.dump(dict(self.result), open(self.filename, "w"))
