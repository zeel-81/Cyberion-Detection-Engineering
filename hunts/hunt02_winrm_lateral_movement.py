from Evtx.Evtx import Evtx
import os
import xml.etree.ElementTree as ET

DATASET = "datasets/EVTX-ATTACK-SAMPLES/Lateral Movement"

for root, dirs, files in os.walk(DATASET):
    for file in files:
        if not file.lower().endswith(".evtx"):
            continue

        path = os.path.join(root, file)

        try:
            with Evtx(path) as log:
                for record in log.records():
                    try:
                        xml = record.xml()
                        root_xml = ET.fromstring(xml)

                        event_id = root_xml.find(".//{*}EventID")
                        if event_id is None or event_id.text != "1":
                            continue

                        image = root_xml.find(".//{*}Data[@Name='Image']")
                        parent = root_xml.find(".//{*}Data[@Name='ParentImage']")
                        command = root_xml.find(".//{*}Data[@Name='CommandLine']")

                        image_text = image.text if image is not None else ""
                        parent_text = parent.text if parent is not None else ""
                        command_text = command.text if command is not None else ""

                        if any(x in (image_text + " " + command_text).lower()
                               for x in ["winrshost.exe", "wsmprovhost.exe", "powershell.exe"]):

                            print("\n--- Finding ---")
                            print(f"File: {os.path.relpath(path, DATASET)}")
                            print(f"Image: {image_text}")
                            print(f"ParentImage: {parent_text}")
                            print(f"CommandLine: {command_text}")

                    except Exception:
                        continue

        except Exception as e:
            print(f"Error reading {path}: {e}")
