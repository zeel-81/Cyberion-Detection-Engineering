from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

EVTX_FILE = "datasets/EVTX-ATTACK-SAMPLES/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx"

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

        if event_id != "13":
            continue

        target_object = ""

        for data in root.findall(".//e:EventData/e:Data", ns):
            if data.attrib.get("Name") == "TargetObject":
                target_object = data.text or ""
                break

        target = target_object.lower()

        if (
            "\\software\\microsoft\\windows\\currentversion\\run\\" in target
            or "\\software\\microsoft\\windows\\currentversion\\runonce\\" in target
        ):
            matches += 1

print("Total events:", total)
print("Registry Run Key matches:", matches)

if matches > 0:
    print("RESULT: DETECTION MATCHED")
else:
    print("RESULT: NO MATCH")
