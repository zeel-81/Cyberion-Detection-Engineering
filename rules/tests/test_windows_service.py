from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

EVTX_FILE = "datasets/EVTX-ATTACK-SAMPLES/Lateral Movement/LM_Remote_Service02_7045.evtx"

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

        image_path = ""
        for data in root.findall(".//e:EventData/e:Data", ns):
            if data.attrib.get("Name") in ("ImagePath", "ServiceFileName"):
                image_path = data.text or ""

        if (
            event_id == "7045"
            and provider_name == "Service Control Manager"
            and "cmd.exe" in image_path.lower()
        ):
            matches += 1

print("Total events:", total)
print("Windows service creation matches:", matches)

if matches > 0:
    print("RESULT: DETECTION MATCHED")
else:
    print("RESULT: NO MATCH")
