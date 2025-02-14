"""
The module provides functionality to analyze APK files and extract various features
such as activities, services, providers, receivers, API calls, suspicious API calls,
and URLs.

Functions
---------
process_apk(apk_file, features_out_dir, logger):
    Processes an APK file and extracts features, saving them to a JSON file if
    specified.

get_from_xml(apk_file, app_obj, logger):
    Extracts activities, services, providers, and receivers from the
    AndroidManifest.xml of an APK file.

get_from_instructions(app_obj, logger):
    Extracts API calls, suspicious API calls, and URLs from the DEX files of an
    APK file.

Part of the following code was taken from: https://github.com/MLDroid/drebin
"""

import json
from pathlib import Path
import re
import os
import time
import zipfile
import logging
from xml.dom import minidom

import lxml
import lxml.etree
import validators
from androguard.core.bytecodes import apk, dvm


def process_apk(apk_file: str, features_out_dir: str, logger: logging.Logger) -> list:
    """
    Process an APK file and extracts features, saving them to a JSON file if
    the output directory is specified.

    Parameters
    ----------
    apk_file: str
        The path to the APK file.
    features_out_dir: str
        The path to the directory where the extracted features are saved.
    logger: logging.Logger
        The logger object.

    Returns
    -------
    list | None
        A list containing the extracted features or None if an error occurred.
    """
    start_time = time.time()

    try:
        logger.debug("start to process %s ...", apk_file)
        app_obj = apk.APK(apk_file)
        activities, services, providers, receivers = get_from_xml(
            apk_file, app_obj, logger
        )
        data_dictionary = {
            "activities": activities,
            "services"  : services,
            "providers" : providers,
            "receivers" : receivers,
        }

        api_calls, suspicious_apis, url_domain = get_from_instructions(app_obj, logger)
        data_dictionary.update(
            {
                "api_calls"       : api_calls,
                "suspicious_calls": suspicious_apis,
                "urls"            : url_domain,
            }
        )

        data_dictionary = {k: list(v) for k, v in data_dictionary.items()}

        if features_out_dir is not None:
            filename_data = Path(features_out_dir) / (Path(apk_file).stem + ".json")
            with Path(filename_data).open("w") as f:
                json.dump(data_dictionary, f)

    except Exception as e:
        final_time = time.time()
        logger.debug(e)
        logger.debug("%s processing failed in %ss...", apk_file, final_time - start_time)
        return None
    else:
        final_time = time.time()
        logger.debug("%s processed successfully in %ss", apk_file, final_time - start_time)
        return [
            f"{k}::{v}"
            for k in data_dictionary
            for v in data_dictionary[k]
            if data_dictionary[k]
        ]


def get_from_xml(apk_file: str, app_obj, logger):
    filename_xml = f"{apk_file}.xml"

    activities = set()
    services = set()
    providers = set()
    receivers = set()

    try:
        apk_file = os.path.abspath(apk_file)
        with open(filename_xml, "w") as f:
            f.write(
                lxml.etree.tostring(
                    app_obj.xml["AndroidManifest.xml"], pretty_print=True
                ).decode()
            )
    except Exception as e:
        logger.debug(e)
        logger.debug(f"error while reading {apk_file} AndroidManifest.xml")
        if os.path.exists(filename_xml):
            os.remove(filename_xml)
        return
    try:
        with open(filename_xml, "r") as f:
            dom = minidom.parse(f)

        dom_collection = dom.documentElement

        activities.update(
            activity.getAttribute("android:name")
            for activity in dom_collection.getElementsByTagName("activity")
            if activity.hasAttribute("android:name")
        )

        services.update(
            service.getAttribute("android:name")
            for service in dom_collection.getElementsByTagName("service")
            if service.hasAttribute("android:name")
        )

        providers.update(
            provider.getAttribute("android:name")
            for provider in dom_collection.getElementsByTagName("provider")
            if provider.hasAttribute("android:name")
        )

        receivers.update(
            receiver.getAttribute("android:name")
            for receiver in dom_collection.getElementsByTagName("receiver")
            if receiver.hasAttribute("android:name")
        )

    except Exception as e:
        logger.debug(e)
        return activities, services, providers, receivers
    finally:
        if os.path.exists(filename_xml):
            os.remove(filename_xml)
        return activities, services, providers, receivers


def get_from_instructions(app_obj, logger):
    app_sdk = app_obj.get_effective_target_sdk_version()
    # FIXME: hardcoded for now
    if app_sdk > 30:
        use_mapping = 30
    elif app_sdk < 23:
        use_mapping = "older"
    else:
        use_mapping = app_sdk

    with open(
        os.path.join(
            os.path.dirname(__file__), f"resources/perm_mapping_{use_mapping}.json"
        ),
        "r",
    ) as f:
        perm_mapping = json.load(f)

    api_mapping = {api: perm for perm, apis in perm_mapping.items() for api in apis}

    with open(
        os.path.join(os.path.dirname(__file__), "resources/SensitiveApis.txt"), "r"
    ) as f:
        sensitive_apis = [l.strip() for l in f.readlines()]

    api_calls = set()
    suspicious_calls = set()
    url_domains = set()

    api_pattern = re.compile("L.*;->.*\(.+\).*")
    red_api_pattern = re.compile("L(.*)" + re.escape("("))
    url_pattern = re.compile(
        "http[s]?://([\w\d-]+\.)*[\w-]+[\.\:]\w+([\/\?\=\&\#.]?[\w-]+)*\/?"
    )
    ip_pattern = re.compile(
        "(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})"
    )
    # TODO: add ipv6?

    def process_api(signature):
        try:
            red_signature = re.findall(red_api_pattern, signature)[0]
            if red_signature in api_mapping:
                api_calls.add(signature)
            if signature in sensitive_apis:
                suspicious_calls.add(signature)
        except Exception as inst_match_err:
            logger.debug(f"instruct error: {inst_match_err}")

    def parse_url(instruction):
        url = re.search(url_pattern, instruction)
        if url:  # we could validate urls but we may miss special f-strings
            url_domains.add(url.group())
        ip = re.search(ip_pattern, instruction)
        if ip and validators.ipv4(ip.group()):
            url_domains.add(ip.group())

    for dex_name in app_obj.get_dex_names():
        try:
            dex = app_obj.get_file(dex_name)
        except zipfile.BadZipfile:
            continue
        try:
            dx = dvm.DalvikVMFormat(dex)
            for method in (m for m in dx.get_methods() if m.get_code() is not None):
                byte_code = method.get_code().get_bc()
                for instruction in byte_code.get_instructions():
                    instruction = instruction.get_output()
                    if instruction is None:
                        continue
                    signature = re.findall(api_pattern, instruction)
                    if len(signature) != 0:
                        process_api(signature[0])
                    parse_url(instruction)
        except ValueError as e:
            if str(e).startswith("This is not a DEX file!"):
                continue
            else:
                raise e

    return api_calls, suspicious_calls, url_domains
