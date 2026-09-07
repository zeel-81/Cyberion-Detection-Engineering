from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

EVTX_FILE = "datasets/EVTX-ATTACK-SAMPLES/Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx"

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

        if event_id != "10":
            continue

        target_image = ""
        granted_access = ""

        for data in root.findall(".//e:EventData/e:Data", ns):
            name = data.attrib.get("Name")
            value = data.text or ""

            if name == "TargetImage":
                target_image = value
            elif name == "GrantedAccess":
                granted_access = value

        if (
            target_image.lower().endswith("\\lsass.exe")
            and granted_access.lower() == "0x00001010"
        ):
            matches += 1

print("Total events:", total)
print("LSASS access matches:", matches)

if matches > 0:
    print("RESULT: DETECTION MATCHED")
else:
    print("RESULT: NO MATCH")
