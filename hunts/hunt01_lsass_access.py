from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path("datasets/EVTX-ATTACK-SAMPLES")

ns = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}

total_events = 0
lsass_access = []

for evtx_file in ROOT.rglob("*.evtx"):
    try:
        with Evtx(str(evtx_file)) as log:
            for record in log.records():
                total_events += 1
                root = ET.fromstring(record.xml())

                event_id = root.findtext(".//e:EventID", namespaces=ns)

                if event_id != "10":
                    continue

                source_image = ""
                target_image = ""
                granted_access = ""

                for data in root.findall(".//e:EventData/e:Data", ns):
                    name = data.attrib.get("Name")
                    value = data.text or ""

                    if name == "SourceImage":
                        source_image = value
                    elif name == "TargetImage":
                        target_image = value
                    elif name == "GrantedAccess":
                        granted_access = value

                if target_image.lower().endswith("\\lsass.exe"):
                    lsass_access.append({
                        "file": str(evtx_file.relative_to(ROOT)),
                        "source": source_image,
                        "target": target_image,
                        "access": granted_access
                    })

    except Exception as exc:
        print(f"[WARN] {evtx_file}: {exc}")

print("Total events analyzed:", total_events)
print("LSASS access events:", len(lsass_access))

for item in lsass_access[:50]:
    print("\n--- Finding ---")
    print("File:", item["file"])
    print("SourceImage:", item["source"])
    print("TargetImage:", item["target"])
    print("GrantedAccess:", item["access"])
