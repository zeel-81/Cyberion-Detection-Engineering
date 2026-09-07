from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

EVTX_FILE = "datasets/EVTX-ATTACK-SAMPLES/Persistence/Network_Service_Guest_added_to_admins_4732.evtx"

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

        if (
            event_id == "4732"
            and provider_name == "Microsoft-Windows-Security-Auditing"
        ):
            matches += 1

print("Total events:", total)
print("Local group membership matches:", matches)

if matches > 0:
    print("RESULT: DETECTION MATCHED")
else:
    print("RESULT: NO MATCH")
