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
import logging
import re
import time
import zipfile
from pathlib import Path
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

    except Exception as e:  # noqa: BLE001
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


def get_from_xml(apk_file: str, app_obj: apk.APK, logger: logging.Logger) -> tuple:
    """
    Extract activities, services, providers, and receivers from the AndroidManifest.xml
    of an APK file.

    Parameters
    ----------
    apk_file: str
        The path to the APK file.
    app_obj: apk.APK
        The APK object.
    logger: logging.Logger
        The logger object.

    Returns
    -------
    tuple
        A tuple containing the extracted activities, services, providers, and receivers.
    """
    filename_xml = f"{apk_file}.xml"

    activities = set()
    services   = set()
    providers  = set()
    receivers  = set()

    try:
        apk_file = Path(apk_file).resolve()
        with Path(filename_xml).open("w") as f:
            f.write(
                lxml.etree.tostring(
                    app_obj.xml["AndroidManifest.xml"], pretty_print=True
                ).decode()
            )
    except Exception as e:  # noqa: BLE001
        logger.debug(e)
        logger.debug("error while reading %s AndroidManifest.xml", apk_file)
        if Path(filename_xml).exists:
            Path(filename_xml).unlink()
        return activities, services, providers, receivers

    try:
        with Path(filename_xml).open("r") as f:
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
        if Path(filename_xml).exists():
            Path(filename_xml).unlink()

    return activities, services, providers, receivers


def get_from_instructions(app_obj: apk.APK, logger: logging.Logger) -> tuple:  # noqa: C901, PLR0915
    """
    Extract API calls, suspicious API calls, and URLs from the DEX files of an APK file.

    Parameters
    ----------
    app_obj: apk.APK
        The APK object.
    logger: logging.Logger
        The logger object.

    Returns
    -------
    tuple
        A tuple containing the extracted API calls, suspicious API calls, and URLs.
    """
    app_sdk = app_obj.get_effective_target_sdk_version()

    # FIXME: hardcoded for now
    if app_sdk > 30:
        use_mapping = 30
    elif app_sdk < 23:
        use_mapping = "older"
    else:
        use_mapping = app_sdk

    with (
        Path(__file__).parent / f"resources/perm_mapping_{use_mapping}.json"
    ).open() as f:
        perm_mapping = json.load(f)

    api_mapping = {api: perm for perm, apis in perm_mapping.items() for api in apis}

    with (Path(__file__).parent / "resources/SensitiveApis.txt").open() as f:
        sensitive_apis = [l.strip() for l in f.readlines()]

    api_calls        = set()
    suspicious_calls = set()
    url_domains      = set()

    api_pattern     = re.compile("L.*;->.*\(.+\).*")  # noqa: W605
    red_api_pattern = re.compile("L(.*)" + re.escape("("))
    url_pattern     = re.compile(
        "http[s]?://([\w\d-]+\.)*[\w-]+[\.\:]\w+([\/\?\=\&\#.]?[\w-]+)*\/?"  # noqa: W605
    )
    ip_pattern      = re.compile(
        "(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})"  # noqa: W605
    )

    # TODO: add ipv6?

    def _process_api(signature: str) -> None:
        try:
            red_signature = re.findall(red_api_pattern, signature)[0]
            if red_signature in api_mapping:
                api_calls.add(signature)
            if signature in sensitive_apis:
                suspicious_calls.add(signature)
        except Exception as inst_match_err:
            logger.debug("instruct error: %s", inst_match_err)

    def _parse_url(instruction: str) -> None:
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
                        _process_api(signature[0])
                    _parse_url(instruction)
        except ValueError as e:
            if str(e).startswith("This is not a DEX file!"):
                continue
            else:
                raise e

    return api_calls, suspicious_calls, url_domains
