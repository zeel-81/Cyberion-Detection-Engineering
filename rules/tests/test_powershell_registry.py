from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

EVTX_FILE = "datasets/EVTX-ATTACK-SAMPLES/Defense Evasion/DE_Powershell_CLM_Disabled_Sysmon_12.evtx"

ns = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}

total = 0
matches = 0

with Evtx(EVTX_FILE) as log:
    for record in log.records():
        total += 1

        root = ET.fromstring(record.xml())
        event_id = root.findtext(".//e:EventID", namespaces=ns)

        if event_id != "12":
            continue

        event_type = ""
        image = ""

        for data in root.findall(".//e:EventData/e:Data", ns):
            name = data.attrib.get("Name")
            value = data.text or ""

            if name == "EventType":
                event_type = value
            elif name == "Image":
                image = value

        if (
            event_type == "DeleteValue"
            and image.lower().endswith("\\powershell.exe")
        ):
            matches += 1

print("Total events:", total)
print("Registry deletion matches:", matches)

if matches > 0:
    print("RESULT: DETECTION MATCHED")
else:
    print("RESULT: NO MATCH")
