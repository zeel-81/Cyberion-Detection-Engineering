from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

EVTX_FILE = "datasets/EVTX-ATTACK-SAMPLES/Lateral Movement/smbmap_upload_exec_sysmon.evtx"

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

        parent_image = ""

        for data in root.findall(".//e:EventData/e:Data", ns):
            if data.attrib.get("Name") == "ParentImage":
                parent_image = data.text or ""
                break

        if parent_image.lower().endswith("\\wmiprvse.exe"):
            matches += 1

print("Total events:", total)
print("WMI child-process matches:", matches)

if matches > 0:
    print("RESULT: DETECTION MATCHED")
else:
    print("RESULT: NO MATCH")
