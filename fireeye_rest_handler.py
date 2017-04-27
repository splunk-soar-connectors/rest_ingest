#!/bin/env python
# --
# File: fireeye_rest_handler.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

import sys
import json
from mimetools import Message
from StringIO import StringIO
from parse import parse

ARTIFACT_LABEL_ALERT = "Alert"
ARTIFACT_LABEL_ANALYSIS = "Analysis"

# dictionary that contains the comman keys in the container
_container_common = {
    "description": "Container added by Phantom",
    "run_automation": False  # Don't run any playbooks, when this container is added
}
_artifact_common = {
    "type": "network",
    "description": "Artifact added by Phantom",
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}


def _get_value(in_dict, in_key, def_val=None, strip_it=True):

    if (in_key not in in_dict):
        return def_val

    if (type(in_dict[in_key]) != str) and (type(in_dict[in_key]) != unicode):
        return in_dict[in_key]

    value = in_dict[in_key].strip() if (strip_it) else in_dict[in_key]

    return value if len(value) else def_val


def _set_cef_key(src_dict, src_key, dst_dict, dst_key):

    src_value = _get_value(src_dict, src_key)

    # if None, try again after removing the @ char
    if (src_value is None):
        if (src_key.startswith('@')):
            return _set_cef_key(src_dict, src_key[1:], dst_dict, dst_key)
        return False

    dst_dict[dst_key] = src_value

    return True


def set_url(http_header, cef):

    # get the request line
    request, header_str = http_header.split('\r\n', 1)

    headers = Message(StringIO(header_str))

    # Remove multiple spaces if any. always happens in http request line
    request = ' '.join(request.split())

    url = request.split()[1]

    if (url):
        host = headers['Host']
        if (url.startswith('http') is False):
            if (host):
                url = 'http://{0}{1}'.format(host, url)

        cef['requestURL'] = url

    return


def parse_time(input_time):

    # format to match "2013-03-28 22:41:39+00"
    result = parse("{year}-{month}-{day} {hour}:{min}:{secs}+00", input_time)
    if (result is not None):
        return "{year}-{month}-{day}T{hour}:{min}:{secs}.0Z".format(**result.named)

    # format to match "2013-03-28T22:41:39Z"
    result = parse("{year}-{month}-{day}T{hour}:{min}:{secs}Z", input_time)
    if (result is not None):
        return "{year}-{month}-{day}T{hour}:{min}:{secs}.0Z".format(**result.named)

    # Return the input as is, if the rest endpoint does not like it, it will return an error
    return input_time


def parse_alert(alert, result):

    new_data = {}
    result.append(new_data)

    # Create the container, each alert represents a container
    container = dict()
    new_data['container'] = container
    container.update(_container_common)
    container['name'] = alert.get('@name', alert.get('name'))

    if ('@id' not in alert):
        if ('id' not in alert):
            raise TypeError('id key not found in alert')

    container['source_data_identifier'] = alert.get('@id', alert.get('id'))
    container['data'] = alert
    start_time = alert.get('occurred')
    if start_time:
      start_time = parse_time(start_time)
      container['start_time'] = start_time
    severity = alert.get('@severity', alert.get('severity', 'medium'))
    container['severity'] = 'high' if severity == 'crit' else 'medium'

    artifact_label = ARTIFACT_LABEL_ALERT

    if (container['name'] == 'malware-object'):
        artifact_label = ARTIFACT_LABEL_ANALYSIS

    # now the artifacts
    new_data['artifacts'] = artifacts = []

    artifact = dict()
    artifacts.append(artifact)

    artifact.update(_container_common)
    artifact.update(_artifact_common)
    artifact['label'] = artifact_label
    artifact_id = len(artifacts)
    artifact['name'] = "Artifact ID: {0}".format(artifact_id)
    artifact['source_data_identifier'] = str(artifact_id)
    start_time = alert.get('occurred')
    if start_time:
      start_time = parse_time(start_time)
      container['start_time'] = start_time

    artifact['cef'] = cef = dict()

    dst = alert.get('dst')
    if (dst):
        _set_cef_key(dst, 'host', cef, 'destinationHostName')
        _set_cef_key(dst, 'ip', cef, 'destinationAddress')
        _set_cef_key(dst, 'port', cef, 'destinationPort')
        _set_cef_key(dst, 'mac', cef, 'destinationMacAddress')

    src = alert.get('src')
    if (src):
        _set_cef_key(src, 'host', cef, 'sourceHostName')
        _set_cef_key(src, 'ip', cef, 'sourceAddress')
        _set_cef_key(src, 'port', cef, 'sourcePort')
        _set_cef_key(src, 'mac', cef, 'sourceMacAddress')

    intf = alert.get('interface')
    if (intf):
        _set_cef_key(intf, 'interface', cef, 'deviceInboundInterface')

    explanation = alert.get('explanation')
    if (explanation):
        _set_cef_key(explanation, '@protocol', cef, 'transportProtocol')

    # Artifact for malware-detected
    mal_detected = explanation.get('malware-detected')
    if (mal_detected):
        malware = mal_detected.get('malware')
        if (malware):
            artifact = dict()
            artifacts.append(artifact)
            artifact.update(_container_common)
            artifact.update(_artifact_common)
            artifact['label'] = artifact_label
            artifact['source_data_identifier'] = len(artifacts)
            artifact['name'] = "Malware Detected "
            artifact['cef'] = cef = dict()
            cef['cs1Label'] = 'signatureName'
            _set_cef_key(malware, '@name', cef, 'cs1')
            cef['cs2Label'] = 'signatureId'
            _set_cef_key(malware, '@sid', cef, 'cs2')
            _set_cef_key(malware, 'application', cef, 'fileName')
            _set_cef_key(malware, 'original', cef, 'filePath')
            _set_cef_key(malware, 'md5sum', cef, 'fileHash')
            _set_cef_key(malware, 'downloaded-at', cef, 'fileCreateTime')
            cef['cs3Label'] = 'httpHeader'
            _set_cef_key(malware, 'http-header', cef, 'cs3')
            if ('http-header' in malware):
                set_url(cef['cs3'], cef)

    # Artifact for cnc-services
    cnc_services = explanation.get('cnc-services')
    if (cnc_services):
        cnc_service = cnc_services.get('cnc-service')
        if (cnc_service):
            if (type(cnc_service) == dict):
                cnc_services_list = []
                cnc_services_list.append(cnc_service)
                cnc_service = cnc_services_list

            for i, service in enumerate(cnc_service):
                artifact = dict()
                artifacts.append(artifact)
                artifact.update(_container_common)
                artifact.update(_artifact_common)
                artifact['label'] = artifact_label
                artifact['source_data_identifier'] = len(artifacts)
                artifact['name'] = "CNC Service # {0}".format(i)
                artifact['cef'] = cef = dict()
                _set_cef_key(service, '@port', cef, 'destinationPort')
                _set_cef_key(service, '@protocol', cef, 'transportProtocol')
                _set_cef_key(service, 'address', cef, 'destinationAddress')
                cef['deviceDirection'] = 'out'
                cef['cs1Label'] = 'channel'
                _set_cef_key(service, 'channel', cef, 'cs1')
                if ('channel' in service):
                    sanitized_header = cef['cs1'].replace('::~~', '\r\n')
                    try:
                        set_url(sanitized_header, cef)
                    except:
                        # Most probably, not a valid http header
                        pass

    return


def parse_json(input_json):

    result = []

    try:
        fe_json = json.loads(input_json)
    except Exception as e:
        return "Unable to parse input json file, possibly incorrect format. Parse Error: {0}".format(e.message)

    alerts = fe_json.get('alert')

    source_device_name = fe_json.get('@appliance', fe_json.get('appliance', ''))

    _artifact_common['deviceHostname'] = source_device_name

    if (type(alerts) == dict):
        alerts_list = []
        alerts_list.append(alerts)
        alerts = alerts_list

    for alert in alerts:
        parse_alert(alert, result)

    return result


def handle_request(request):
    return parse_json(request.body)

if __name__ == '__main__':

    with open(sys.argv[1]) as f:
        result = parse_json(str(f.read()))
        # import pprint;pprint.pprint(result)
        print(json.dumps(result))

    exit(0)
