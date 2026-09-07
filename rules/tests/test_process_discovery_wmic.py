from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

EVTX_FILE = "datasets/EVTX-ATTACK-SAMPLES/Execution/exec_wmic_xsl_internet_sysmon_3_1_11.evtx"

ns = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}

matches = 0
total = 0

with Evtx(EVTX_FILE) as log:
    for record in log.records():
        total += 1
        root = ET.fromstring(record.xml())

        event_id = root.findtext(".//e:EventID", namespaces=ns)

        if event_id != "1":
            continue

        image = ""
        command_line = ""

        for data in root.findall(".//e:EventData/e:Data", ns):
            name = data.attrib.get("Name")
            value = data.text or ""

            if name == "Image":
                image = value
            elif name == "CommandLine":
                command_line = value

        cmd = command_line.lower()

        if (
            image.lower().endswith("\\wmic.exe")
            and "process" in cmd
            and "list" in cmd
        ):
            matches += 1

print("Total events:", total)
print("WMIC process discovery matches:", matches)

if matches > 0:
    print("RESULT: DETECTION MATCHED")
else:
    print("RESULT: NO MATCH")
