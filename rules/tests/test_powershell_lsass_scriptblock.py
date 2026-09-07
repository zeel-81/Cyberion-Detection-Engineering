from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

EVTX_FILE = (
    "datasets/EVTX-ATTACK-SAMPLES/"
    "Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx"
)

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

        if event_id != "4104":
            continue

        script_block = ""

        for data in root.findall(".//e:EventData/e:Data", ns):
            if data.attrib.get("Name") == "ScriptBlockText":
                script_block = data.text or ""
                break

        text = script_block.lower()

        if "minidumpwritedump" in text and "lsass" in text:
            matches += 1

print("Total events:", total)
print("Suspicious PowerShell script block matches:", matches)

if matches > 0:
    print("RESULT: DETECTION MATCHED")
else:
    print("RESULT: NO MATCH")
