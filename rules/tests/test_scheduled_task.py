from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

EVTX_FILE = "datasets/EVTX-ATTACK-SAMPLES/Execution/temp_scheduled_task_4698_4699.evtx"

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

        # Our Sigma rule condition:
        # EventID: 4698
        if event_id == "4698":
            matches += 1

print(f"Total events checked: {total}")
print(f"Events matching EventID 4698: {matches}")

if matches > 0:
    print("RESULT: DETECTION MATCHED")
else:
    print("RESULT: NO MATCH")
