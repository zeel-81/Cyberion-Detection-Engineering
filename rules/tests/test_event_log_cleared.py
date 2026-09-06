from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

EVTX_FILE = "datasets/EVTX-ATTACK-SAMPLES/Defense Evasion/DE_104_system_log_cleared.evtx"

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
        provider = root.find(".//e:Provider", ns)

        provider_name = provider.attrib.get("Name", "") if provider is not None else ""

        if event_id == "104" and provider_name == "Microsoft-Windows-Eventlog":
            matches += 1

print("Total events:", total)
print("Event log clearing matches:", matches)

if matches > 0:
    print("RESULT: DETECTION MATCHED")
else:
    print("RESULT: NO MATCH")
