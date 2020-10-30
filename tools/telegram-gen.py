import argparse
import json
import os
import shutil
from inspect import getsourcefile
from pathlib import Path
from typing import List, Tuple

import lxml.etree as etree
import requests

# https://stackoverflow.com/questions/2632199/how-do-i-get-the-path-of-the-current-executed-file-in-python/18489147#18489147
SCRIPT_DIR = os.path.dirname(os.path.abspath(getsourcefile(lambda: 0)))

EEP_DESCRIPTOR_URL = "http://tools.enocean-alliance.org/EEPViewer/eep-viewer-desc.json"
EEP_PROFILE_URL_FORMAT = (
    "http://tools.enocean-alliance.org/EEPViewer/profiles/{rorg:02X}/{func:02X}/{type:02X}/"
    "{rorg:02X}-{func:02X}-{type:02X}.{ext}"
)

EEP_OUT_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "doc", "enocean", "eep"))
EEP_PDF_FILE_PATH = os.path.normpath(
    os.path.join(
        EEP_OUT_DIR, "{rorg:02X}", "{func:02X}", "{rorg:02X}-{func:02X}-{type:02X}.pdf"
    )
)
EEP_XML_FILE_PATH = os.path.normpath(
    os.path.join(
        EEP_OUT_DIR, "{rorg:02X}", "{func:02X}", "{rorg:02X}-{func:02X}-{type:02X}.xml"
    )
)


# =============================================================================
# Descriptor download
# =============================================================================
def download_eep_descriptors() -> List[Tuple[int, int, int]]:
    with requests.get(EEP_DESCRIPTOR_URL) as response:
        response.raise_for_status()
        json_data = json.loads(response.text)

        eep_list = []
        for rorg_key in json_data:
            eep_rorg = rorg_key if isinstance(rorg_key, int) else int(rorg_key, 16)

            func_list = json_data[rorg_key]["function"]
            if not isinstance(func_list, list):
                func_list = [func_list]

            for func_obj in func_list:
                eep_func = func_obj["value"]
                if not isinstance(eep_func, int):
                    eep_func = int(eep_func, 16)

                type_list = func_obj["type"]
                if not isinstance(type_list, list):
                    type_list = [type_list]

                for type_obj in type_list:
                    eep_type = type_obj["value"]
                    if not isinstance(eep_type, int):
                        eep_type = int(eep_type, 16)

                    eep_list.append((eep_rorg, eep_func, eep_type))

        return eep_list


def create_eep_xml_parser(encoding: str = None):
    return etree.XMLParser(
        encoding=encoding,
        remove_comments=True,
        dtd_validation=False,
        load_dtd=False,
        remove_pis=True,
        remove_blank_text=True,
    )


def download_eep_pdf(
    eep_rorg: int, eep_func: int, eep_type: int, out_path: Path
) -> None:
    url = EEP_PROFILE_URL_FORMAT.format(
        rorg=eep_rorg, func=eep_func, type=eep_type, ext="pdf"
    )

    # Get the raw data
    with requests.get(url, stream=True) as r:
        r.raise_for_status()

        if not out_path.parent.exists():
            out_path.parent.mkdir(parents=True)

        with out_path.open("wb") as f:
            for chunk in r.iter_content(chunk_size=10240):
                if chunk:
                    f.write(chunk)


def download_eep_xml(
    eep_rorg: int, eep_func: int, eep_type: int, out_path: Path
) -> None:
    url = EEP_PROFILE_URL_FORMAT.format(
        rorg=eep_rorg, func=eep_func, type=eep_type, ext="xml"
    )

    # Get the raw data
    with requests.get(url) as r:
        # Load the XML
        # As some files declare UTF-16 encoding but are UTF-8 encoded (eg. A5-30-06)
        # or windows1252 encoded (eg. D2-14-52) we try these two alternate encodings as fallback.
        # Not super clean but the XML files provided by the EnOcean Alliance are messy
        try:
            # First try without explicit encoding
            xml = etree.fromstring(r.content, create_eep_xml_parser())
        except etree.XMLSyntaxError:
            try:
                # Attempt to decode using UTF-8
                xml = etree.fromstring(r.content, create_eep_xml_parser("UTF-8"))
            except etree.XMLSyntaxError:
                # Attempt to decode using Windows1252
                xml = etree.fromstring(r.content, create_eep_xml_parser("windows-1252"))

    # Now we trim all useless whitespaces
    for elem in xml.iter("*"):
        if elem.text is not None:
            elem.text = elem.text.strip()
        # if elem.tail is not None:
        #     elem.tail = elem.tail.strip()

    # Then write out nice, clean and pretty-printed XML
    xml_tree = etree.ElementTree(xml)

    if not out_path.parent.exists():
        out_path.parent.mkdir(parents=True)
    xml_tree.write(str(out_path), pretty_print=True)


def run_download():
    print("Fetching EEP list...", end="")
    eep_list = download_eep_descriptors()
    print(f" DONE : {len(eep_list)} EEP found.")

    # Prepares the XML & PDF output directories
    print(f"Cleaning content of PDF output directory {EEP_OUT_DIR}...")
    if os.path.exists(EEP_OUT_DIR):
        shutil.rmtree(EEP_OUT_DIR)

    # Download XML and PDF files
    for idx, (eep_rorg, eep_func, eep_type) in enumerate(eep_list):
        eep = f"{eep_rorg:02X}-{eep_func:02X}-{eep_type:02X}"
        print(f"Fetching EEP '{eep}' ({idx + 1}/{len(eep_list)}): ", end="", flush=True)

        download_eep_pdf(
            eep_rorg,
            eep_func,
            eep_type,
            Path(EEP_PDF_FILE_PATH.format(rorg=eep_rorg, func=eep_func, type=eep_type)),
        )
        print("PDF ok,", end="", flush=True)
        download_eep_xml(
            eep_rorg,
            eep_func,
            eep_type,
            Path(EEP_XML_FILE_PATH.format(rorg=eep_rorg, func=eep_func, type=eep_type)),
        )
        print(" XML ok", flush=True)


# =============================================================================
# Code Generation
# =============================================================================
def run_generate():
    print("Generating...")


# =============================================================================
# Main
# =============================================================================
parser = argparse.ArgumentParser(description="EEP Telegram generation tool")
parser.add_argument(
    "-d",
    "--download",
    help="Download the definitions from the EnOcean website",
    action="store_true",
)
parser.add_argument(
    "-g",
    "--generate",
    help="Generate the code from the EnOcean definitions",
    action="store_true",
)

args = parser.parse_args()
if not (args.download or args.generate):
    parser.error("no action specified")

if args.download:
    run_download()
if args.generate:
    run_generate()
