#!/usr/bin/env python2.7
# File: stix_rest_handler.py
# Copyright (c) 2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
import libtaxii as lt
from stix.core import STIXPackage
from collections import OrderedDict
from jsonpath_rw import parse as jp_parse
from six import string_types
import uuid
from copy import deepcopy
import json
from phantom_common.compat import StringIO

# dictionary that contains the common keys in the container
_container_common = {
    "description": "Container added by Phantom",
    "run_automation": False  # Don't run any playbooks, when this container is added
}
_artifact_common = {
    "type": "network",
    "description": "Artifact added by Phantom",
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}


def process_results(results):
    processed_results = []

    for i, result in enumerate(results):

        # container is a dictionary of a single container and artifacts
        if 'container' not in result:
            continue

        # container is a dictionary of a single container and artifacts
        if not result.get('artifacts'):
            # igonore containers without artifacts
            continue

        for j, artifact in enumerate(result['artifacts']):

            if 'source_data_identifier' not in artifact:
                artifact['source_data_identifier'] = j

            artifact.update(_artifact_common)

        processed_results.append(result)

    return processed_results


def handle_request(f):
    # The django request object does not support seek, so move it to cSTringIO
    cstrio = StringIO()
    cstrio.write(f.read().decode('utf-8'))
    cstrio.seek(0)

    # first try to parse it as a taxii message
    try:
        taxii_msg = lt.tm11.get_message_from_xml(cstrio.read())
    except:
        # Now as a a stix document
        cstrio.seek(0)
        package = parse_stix(cstrio)

        if type(package) == str:
            # Error
            return package

        packages = [package]
        results = parse_packages(packages, None)
    else:
        results = parse_taxii_message(taxii_msg, None)

    # import pprint;pprint.pprint(results)
    # with open('/tmp/taxii-parsed.json', 'w') as f:
    #     f.write(json.dumps(results, indent=' ' * 4))

    return process_results(results)

# -------- Stix -------


get_list = lambda x: x if type(x) is list else [x]


def parse_domain_obj_type(prop, obs_json):
    if 'value' not in prop:
        return

    value = prop['value']

    if isinstance(value, string_types):
        cef = dict()
        artifact = dict()
        _set_cef_key(prop, 'value', cef, 'destinationDnsDomain')

        # so this artifact needs to be added
        artifact['name'] = "Domain Object"
        artifact['cef'] = cef
        # append to the properties
        obs_json['properties'].append(artifact)
    elif type(value) == dict:
        if 'value' in value:
            value = value['value']
            value = get_list(value)  # convert to list, removes requirement for if else
            for addr in value:
                cef = dict()
                artifact = dict()
                cef['destinationDnsDomain'] = addr
                # so this artifact needs to be added
                artifact['name'] = "Domain Object"
                artifact['cef'] = cef
                # append to the properties
                obs_json['properties'].append(artifact)

    return


def parse_hash_object(file_hash, obs_json, file_name=None, file_size=None, file_path=None):
    if file_hash is None:
        return

    if 'simple_hash_value' not in file_hash:
        return

    hash_value = file_hash['simple_hash_value']

    ret_val = False

    if isinstance(hash_value, string_types):
        cef = dict()
        _set_cef_key(file_hash, 'simple_hash_value', cef, 'fileHash')
        if len(cef) == 0:
            return
        if file_name:
            cef['fileName'] = file_name
        if file_size:
            cef['fileSize'] = file_size
        if file_path:
            cef['filePath'] = file_path
        artifact = dict()
        # so this artifact needs to be added
        artifact['name'] = "File Object"
        artifact['cef'] = cef
        # append to the properties
        obs_json['properties'].append(artifact)
        return True
    elif type(hash_value) == dict:
        if 'value' in hash_value:
            value = hash_value['value']
            value = get_list(value)  # convert to list, removes requirement for if else
            for curr_hash in value:
                cef = dict()
                artifact = dict()
                cef['fileHash'] = curr_hash
                if file_name:
                    cef['fileName'] = file_name
                if file_size:
                    cef['fileSize'] = file_size
                if file_path:
                    cef['filePath'] = file_path
                # so this artifact needs to be added
                artifact['name'] = "File Object"
                artifact['cef'] = cef
                # append to the properties
                obs_json['properties'].append(artifact)
                ret_val = True

    return ret_val


def parse_file_name_obj(file_name, prop):
    if type(file_name) == dict:
        value = file_name.get('value')
        if not value:
            return None

        condition = file_name.get('condition')
        if condition.lower() == 'contains':
            return "*{0}*".format(value)
        elif condition.lower() == 'equals':
            return value

    return None


def parse_file_path_obj(file_path, prop):
    if type(file_path) == dict:
        value = file_path.get('value')
        if not value:
            return None

        condition = file_path.get('condition')
        if condition.lower() == 'contains':
            return "*{0}*".format(value)
        elif condition.lower() == 'equals':
            return value

    return None


def parse_email_address(email_object, email_type, prop, obs_json):
    if not email_object:
        return

    cef_key = 'cs1' if (email_type == 'from') else 'cs2'
    cef_label = 'fromEmail' if (email_type == 'from') else 'toEmail'

    category = email_object.get('category')

    if not category:
        return

    if (category != 'e-mail') and (category != 'email'):
        return

    if email_object.get('xsi:type') != 'AddressObjectType':
        return

    email_addr_value = email_object.get('address_value')
    if not email_addr_value:
        return

    artifacts = parse_common_obj_type(email_addr_value, obs_json, 'value', cef_key, 'Email Object')
    try:
        for artifact in artifacts:
            artifact['cef']['cs1Label'] = cef_label
    except:
        pass

    return


def parse_email_obj_type(prop, obs_json):
    header = prop.get('header')

    if not header:
        return

    from_object = header.get('from')

    if from_object:
        parse_email_address(from_object, 'from', prop, obs_json)

    to_object = header.get('to')

    if to_object:
        parse_email_address(to_object, 'to', prop, obs_json)

    subject_object = header.get('subject')

    if subject_object:
        artifacts = parse_common_obj_type(subject_object, obs_json, 'value', 'cs3', 'Email Object')
        try:
            for artifact in artifacts:
                artifact['cef']['cs3Label'] = 'subject'
        except:
            pass

    return


def parse_win_reg_key_obj_type(prop, obs_json):
    hive = prop.get('hive')

    if not hive:
        return

    cef = {}
    _set_cef_key(hive, 'value', cef, 'cs1', 'cs1Label', 'hive')

    key = prop.get('key')
    if key:
        _set_cef_key(key, 'value', cef, 'cs2', 'cs2Label', 'key')

    values = prop.get('values')

    for value in values:

        if not value:
            continue

        name = value.get('name')

        if not name:
            continue

        data = value.get('data')

        if not data:
            continue

        curr_cef = dict(cef)

        _set_cef_key(name, 'value', curr_cef, 'cs3', 'cs3Label', 'name')
        _set_cef_key(data, 'value', curr_cef, 'cs4', 'cs4Label', 'data')

        artifact = dict()
        artifact['name'] = "Registry Object"
        artifact['cef'] = curr_cef
        obs_json['properties'].append(artifact)

    return


def parse_file_obj_type(prop, obs_json):
    # Check if hashes are present
    hashes = prop.get('hashes')
    file_name = prop.get('file_name')
    file_size = prop.get('size_in_bytes')
    file_path = prop.get('file_path')

    if file_path:
        file_path = parse_file_path_obj(file_path, prop)

    if file_name:
        file_name = parse_file_name_obj(file_name, prop)

    hash_added = 0

    if hashes:
        for curr_hash in hashes:
            hash_added |= parse_hash_object(curr_hash, obs_json, file_name, file_size, file_path)

        if hash_added:
            # FileHash added, no need to add anymore properties
            return

    # if hashes could not be added for some reason (or not present), need
    # to add the file name and size if available as an artifact on it's own
    cef = dict()
    _set_cef_key(prop, 'file_name', cef, 'fileName')
    _set_cef_key(prop, 'size_in_bytes', cef, 'fileSize')
    if file_path:
        cef['filePath'] = file_path
    if len(cef) == 0:
        return
    artifact = dict()
    artifact['name'] = "File Object"
    artifact['cef'] = cef
    obs_json['properties'].append(artifact)

    return


def parse_port_obj_type(prop, obs_json):
    # first store the protocol value
    protocol_value = prop.get('layer4_protocol')

    if protocol_value is None:
        # keep it empty
        protocol_value = dict()

    port_value = prop.get('port_value')

    if port_value is None:
        return

    if isinstance(port_value, string_types):
        artifact = dict()
        cef = dict()
        _set_cef_key(protocol_value, 'value', cef, 'transportProtocol')
        _set_cef_key(prop, 'port_value', cef, 'destinationPort')
        # so this artifact needs to be added
        artifact['name'] = "Port Object"
        artifact['cef'] = cef
        # append to the properties
        obs_json['properties'].append(artifact)

    elif type(port_value) == dict:
        condition = port_value.get('condition')
        if condition is None:
            return

        value = port_value.get('value')
        if condition == 'InclusiveBetween':
            artifact = dict()
            cef = dict()
            _set_cef_key(protocol_value, 'value', cef, 'transportProtocol')
            cef['destinationPort'] = '-'.join(value)
            artifact['name'] = "Port Object"
            artifact['cef'] = cef
            # append to the properties
            obs_json['properties'].append(artifact)

        elif condition == 'Equals':
            value = get_list(value)  # convert to list, removes requirement for if else
            for addr in value:
                artifact = dict()
                cef = dict()
                _set_cef_key(protocol_value, 'value', cef, 'transportProtocol')
                cef['destinationPort'] = addr
                artifact['name'] = "Port Object"
                artifact['cef'] = cef
                # append to the properties
                obs_json['properties'].append(artifact)

    return


def parse_address_obj_type(prop, obs_json):
    addr_value = prop.get('address_value')

    if addr_value is None:
        return

    if isinstance(addr_value, string_types):
        artifact = dict()
        cef = dict()
        _set_cef_key(prop, 'address_value', cef, 'destinationAddress')
        # so this artifact needs to be added
        artifact['name'] = "Address Object"
        artifact['cef'] = cef
        # append to the properties
        obs_json['properties'].append(artifact)

    elif type(addr_value) == dict:
        condition = addr_value.get('condition')
        if condition is None:
            return

        value = addr_value.get('value')
        if condition == 'InclusiveBetween':
            artifact = dict()
            cef = dict()
            cef['destinationAddress'] = '-'.join(value)
            artifact['name'] = "Address Object"
            artifact['cef'] = cef
            # append to the properties
            obs_json['properties'].append(artifact)
        elif condition == 'Equals':
            value = get_list(value)  # convert to list, removes requirement for if else
            for addr in value:
                artifact = dict()
                cef = dict()
                cef['destinationAddress'] = addr
                artifact['name'] = "Address Object"
                artifact['cef'] = cef
                # append to the properties
                obs_json['properties'].append(artifact)


def parse_common_obj_type(prop, obs_json, key_name, cef_key, artifact_name):
    addr_value = prop.get(key_name)

    if addr_value is None:
        return None

    artifacts = []

    if isinstance(addr_value, string_types):
        artifact = dict()
        cef = dict()
        _set_cef_key(prop, key_name, cef, cef_key)
        # so this artifact needs to be added
        artifact['name'] = artifact_name
        artifact['cef'] = cef
        # append to the properties
        artifacts.append(artifact)
        obs_json['properties'].append(artifact)

    elif type(addr_value) == dict:
        condition = addr_value.get('condition')
        if condition is None:
            return None

        value = addr_value.get('value')
        if condition == 'InclusiveBetween':
            artifact = dict()
            cef = dict()
            cef[cef_key] = '-'.join(value)
            artifact['name'] = artifact_name
            artifact['cef'] = cef
            # append to the properties
            artifacts.append(artifacts)
            obs_json['properties'].append(artifact)

        elif condition == 'Equals':
            value = get_list(value)  # convert to list, removes requirement for if else
            for addr in value:
                artifact = dict()
                cef = dict()
                cef[cef_key] = addr
                artifact['name'] = artifact_name
                artifact['cef'] = cef
                # append to the properties
                artifacts.append(artifacts)
                obs_json['properties'].append(artifact)

    return artifacts


def parse_uri_obj_type(prop, obs_json):
    uri_type = prop.get('type')
    if uri_type is None:
        parse_common_obj_type(prop, obs_json, 'value', 'requestURL', 'URI Object')
    elif uri_type == 'Domain Name':
        parse_common_obj_type(prop, obs_json, 'value', 'destinationDnsDomain', 'Domain Object')
    elif uri_type == 'URL':
        parse_common_obj_type(prop, obs_json, 'value', 'requestURL', 'URI Object')

    return


def parse_sock_obj_type(prop, obs_json):
    ip_addr = prop.get('ip_address')

    if ip_addr:
        if ip_addr['xsi:type'] == 'AddressObjectType':
            parse_address_obj_type(ip_addr, obs_json)

    return


def parse_net_conn_obj_type(prop, obs_json):
    dest_sock_addr = prop.get('destination_socket_address')

    if dest_sock_addr:
        if dest_sock_addr['xsi:type'] == 'SocketAddressObjectType':
            parse_sock_obj_type(dest_sock_addr, obs_json)

    return


def parse_property(prop, obs_json):
    try:
        if prop['xsi:type'] == 'FileObjectType':
            parse_file_obj_type(prop, obs_json)
        elif prop['xsi:type'] == 'DomainNameObjectType':
            parse_domain_obj_type(prop, obs_json)
        elif prop['xsi:type'] == 'AddressObjectType':
            parse_address_obj_type(prop, obs_json)
        elif prop['xsi:type'] == 'URIObjectType':
            parse_uri_obj_type(prop, obs_json)
        elif prop['xsi:type'] == 'PortObjectType':
            parse_port_obj_type(prop, obs_json)
        elif prop['xsi:type'] == 'NetworkConnectionObjectType':
            parse_net_conn_obj_type(prop, obs_json)
        elif prop['xsi:type'] == 'EmailMessageObjectType':
            parse_email_obj_type(prop, obs_json)
        elif prop['xsi:type'] == 'WindowsRegistryKeyObjectType':
            parse_win_reg_key_obj_type(prop, obs_json)
    except:
        pass

    return


package_base = OrderedDict({
        'id': '',
        'idref': '',
        'campaigns': None,
        'coas': None,
        'exploit_targets': None,
        'incidents': None,
        'indicators': None,
        'observables': None,
        'related_packages': None,
        'reports': None,
        'threat_actors': None,
        'timestamp': '',
        'ttps': None,
        'version': ''})


def parse_indicator(indicator, package):
    # First check if it is an idref
    idref = indicator.idref
    if idref:
        # An idref means this indicator is defined elsewhere in the document
        # and the parsing code _will_ parse that incident and add artifacts anyways
        # so no need to parse this object
        return None

    jp_expr = jp_parse("$..observable")

    indicator_json = {}
    indicator_id = indicator.id_

    if not indicator_id:
        indicator_id = "Phantom:Indicator-{0}".format(uuid.uuid4())

    package['indicators'][indicator_id] = indicator_json
    indicator_dict = indicator.to_dict()

    # with open("indicator.json", "w") as f:
    #     f.write()

    indicator_json['title'] = indicator_dict.get('title')
    indicator_json['description'] = indicator_dict.get('description')

    indicator_json['input_data'] = json.dumps(indicator.to_json())

    matches = jp_expr.find(indicator_dict)

    if not matches:
        return indicator_id

    indicator_json['observable_idrefs'] = []

    for match in matches:
        observable = match.value
        if 'idref' in observable:
            indicator_json['observable_idrefs'].append(observable['idref'])
            continue

        obs_id = parse_observable(observable, package)
        if obs_id:
            indicator_json['observable_idrefs'].append(obs_id)

    return indicator_id


def parse_construct(construct, name, package):
    jp_expr = jp_parse("$..observables")

    construct_json = {}
    construct_id = construct.id_

    if not construct_id:
        construct_id = "Phantom:{0}-{1}".format(name, uuid.uuid4())

    package['{0}s'.format(name)][construct_id] = construct_json
    construct_dict = construct.to_dict()

    construct_json['title'] = construct_dict.get('title')
    construct_json['description'] = construct_dict.get('description')

    construct_json['input_data'] = json.dumps(construct.to_json())

    matches = jp_expr.find(construct.to_dict())

    if not matches:
        return construct_id

    construct_json['observable_idrefs'] = []

    for match in matches:
        observables = match.value
        for observable in observables:
            if 'idref' in observable:
                construct_json['observable_idrefs'].append(observable['idref'])
                continue

            obs_id = parse_observable(observable, package)
            if obs_id:
                construct_json['observable_idrefs'].append(obs_id)

    return construct_id


def parse_ttp(ttp, package):
    jp_expr = jp_parse("$..observables")

    ttp_json = {}
    ttp_id = ttp.id_

    if not ttp_id:
        ttp_id = "Phantom:ttp-{0}".format(uuid.uuid4())

    package['ttps'][ttp_id] = ttp_json
    ttp_dict = ttp.to_dict()

    ttp_json['title'] = ttp_dict.get('title')
    ttp_json['description'] = ttp_dict.get('description')

    ttp_json['input_data'] = json.dumps(ttp.to_json())

    matches = jp_expr.find(ttp.to_dict())

    if not matches:
        return ttp_id

    ttp_json['observable_idrefs'] = []

    for match in matches:
        observables = match.value
        for observable in observables:
            if 'idref' in observable:
                ttp_json['observable_idrefs'].append(observable['idref'])
                continue

            obs_id = parse_observable(observable, package)
            if obs_id:
                ttp_json['observable_idrefs'].append(obs_id)

    return ttp_id


def parse_report_observables(report, package):
    report_json = {}
    report_id = report.id_

    if not report_id:
        report_id = "Phantom:report-{0}".format(uuid.uuid4())

    package['reports'][report_id] = report_json
    report_dict = report.to_dict()

    report_json['title'] = report_dict.get('title')
    report_json['description'] = report_dict.get('description')

    report_json['input_data'] = json.dumps(report.to_json())

    report_dict = report.to_dict()

    if 'observables' not in report_dict:
        return report_id

    if 'observables' not in report_dict['observables']:
        return report_id

    report_json['observable_idrefs'] = []

    for observable in report_dict['observables']['observables']:
        if 'idref' in observable:
            report_json['observable_idrefs'].append(observable['idref'])
            continue

        obs_id = parse_observable(observable, package)
        if obs_id:
            report_json['observable_idrefs'].append(obs_id)

    return report_id


def parse_observable(observable, package):
    obs_json = {}
    obs_json['observable_idrefs'] = []

    obs_id = observable.get('id')
    if not obs_id:
        obs_id = "Phantom:Observable-{0}".format(uuid.uuid4())

    package['observables'][obs_id] = obs_json

    # Parse any observables in this observable
    jp_expr = jp_parse("$..observables")

    matches = jp_expr.find(observable)

    if matches:
        for match in matches:
            obs_comps = match.value
            for obs_comp in obs_comps:
                if 'idref' in obs_comp:
                    obs_json['observable_idrefs'].append(obs_comp['idref'])
                    continue

                obs_comp_id = parse_observable(obs_comp, package)
                if obs_comp_id:
                    obs_json['observable_idrefs'].append(obs_comp_id)

    # Parse any object references in this observable
    jp_expr = jp_parse("$..object_reference")

    matches = jp_expr.find(observable)

    if matches:
        for match in matches:
            obj_ref_id = match.value
            obs_json['observable_idrefs'].append(obj_ref_id)
            continue

    # Parse the properties
    jp_expr = jp_parse("$..properties")
    matches = jp_expr.find(observable)

    if not matches:
        return obs_id

    # Parse the properties
    obs_json['properties'] = []
    for match in matches:
        parse_property(match.value, obs_json)

    return obs_id


def parse_report(report, package):
    # Indicators
    if report.indicators:
        if not package.get('indicators'):
            package['indicators'] = OrderedDict()
        for inc in report.indicators:
            parse_indicator(inc, package)

    # Observable
    if report.observables:
        if not package.get('reports'):
            package['reports'] = OrderedDict()
        parse_report_observables(report, package)

    return


def parse_stix(xml_file_object, base_connector=None):
    if xml_file_object is None:
        if base_connector:
            base_connector.debug_print("Invalid input xml_file_object")
        return None

    try:
        stix_pkg = STIXPackage.from_xml(xml_file_object)
    except Exception as e:
        message = "Possibly invalid stix or taxii xml. Error: {0}".format(e.message)
        if base_connector:
            base_connector.debug_print(message)
        return message

    package = OrderedDict(package_base)
    package['id'] = stix_pkg.id_
    if not package['id']:
        package['id'] = "Phantom:Package-{0}".format(uuid.uuid4())

    package['idref'] = stix_pkg.idref
    package['version'] = stix_pkg.version
    package['timestamp'] = str(stix_pkg.timestamp)
    package['observable_idrefs'] = []
    package['observables'] = OrderedDict()
    package['input_data'] = json.dumps(stix_pkg.to_json())

    # Indicators
    if stix_pkg.indicators:
        package['indicators'] = OrderedDict()
        for inc in stix_pkg.indicators:
            parse_indicator(inc, package)

    # TTPs
    if stix_pkg.ttps:
        package['ttps'] = OrderedDict()
        for ttp in stix_pkg.ttps:
            parse_ttp(ttp, package)

    # Reports
    if stix_pkg.reports:
        for report in stix_pkg.reports:
            parse_report(report, package)

    # Observable
    if stix_pkg.observables:
        for observable in stix_pkg.observables:
            if observable.idref:
                package['observable_idrefs'].append(observable.idref)
                continue
            parse_observable(observable.to_dict(), package)

    return package


def _get_value(in_dict, in_key, def_val=None, strip_it=True):
    if in_key not in in_dict:
        return def_val

    if not isinstance(in_dict[in_key], string_types):
        return in_dict[in_key]

    value = in_dict[in_key].strip() if strip_it else in_dict[in_key]

    return value if len(value) else def_val


def _set_cef_key(src_dict, src_key, dst_dict, dst_key, cs_label_key=None, cs_label_value=None):
    src_value = _get_value(src_dict, src_key)

    # Ignore if None
    if src_value is None:
        return False

    dst_dict[dst_key] = src_value

    if cs_label_key:
        dst_dict[cs_label_key] = cs_label_value

    return True


def get_artifacts_from_observable(obs_id, observables, label):
    observable_artifacts = []
    observable = observables.get(obs_id)
    if not observable:
        # We were given an idref that points to an observable that was not defined.
        return observable_artifacts

    if 'observable_idrefs' in observable:
        for observable_idref in observable['observable_idrefs']:
            obs_artifacts = get_artifacts_from_observable(observable_idref, observables, label)
            observable_artifacts.extend(obs_artifacts)

    if 'properties' in observable:
        observable_artifacts.extend(deepcopy(observable['properties']))

    if observable_artifacts:
        for observable_artifact in observable_artifacts:
            observable_artifact['label'] = label
            observable_artifact['source_data_identifier'] = obs_id

    return observable_artifacts


def create_artifacts_from_construct(package, name, observables, artifacts):
    if not package:
        return

    constructs = package.get(name)

    if not constructs:
        return

    for construct in constructs:

        construct_artifacts = []
        curr_construct = constructs[construct]
        if 'observable_idrefs' not in curr_construct:
            continue

        for observable_idref in curr_construct['observable_idrefs']:
            obs_artifacts = get_artifacts_from_observable(observable_idref, observables, name)
            construct_artifacts.extend(obs_artifacts)

        if construct_artifacts:
            # container = {}
            # if (not curr_construct.get('title')):
            #     container['name'] = construct
            # else:
            #     container['name'] = curr_construct['title']
            # container['source_data_identifier'] = construct
            # container['data'] = curr_construct['input_data']
            artifacts.extend(construct_artifacts)

    return


def create_container_from_package(package, observables, base_connector):
    if not package:
        return {}

    artifacts = []

    constructs = ['campaigns', 'coas', 'exploit_targets', 'threat_actors', 'related_packages', 'indicators', 'reports', 'ttps']

    for construct in constructs:
        create_artifacts_from_construct(package, construct, observables, artifacts)

    if not artifacts:
        # The package probably did not contain anything but observables in the package node
        if not observables:
            # Return empty container
            return {}

        # Create a container from the package itself
        if 'observable_idrefs' in package:
            for observable_idref in package['observable_idrefs']:
                obs_arts = get_artifacts_from_observable(observable_idref, observables, 'observable')
                artifacts.extend(obs_arts)

        if 'observables' in package:
            for observable_idref in package['observables']:
                obs_arts = get_artifacts_from_observable(observable_idref, observables, 'observable')
                artifacts.extend(obs_arts)

    if artifacts:
        container = {}
        container['name'] = package['id']
        container['source_data_identifier'] = package['id']
        container['data'] = package['input_data']
        return {'container': container, 'artifacts': artifacts}

    # Return empty container
    return {}


def parse_packages(packages, base_connector):
    containers = []

    if not packages:
        if base_connector:
            base_connector.save_progress("Zero packages found")
        return containers

    # get all the observables
    if base_connector:
        base_connector.send_progress("Extracting Observables")

    jp_expr = jp_parse("$..observables")

    all_observables = OrderedDict()

    matches = jp_expr.find(packages)
    for match in matches:
        try:
            all_observables.update(match.value)
        except:
            raise

    if base_connector:
        base_connector.send_progress(" ")

    if base_connector:
        base_connector.save_progress("Creating Containers and Artifacts from {0} packages".format(len(packages)))

    # Now look at each of the package
    for j, package in enumerate(packages):
        if base_connector:
            base_connector.send_progress("Working on STIX Package # {0}".format(j))
        package_containers = create_container_from_package(package, all_observables, base_connector)
        if package_containers:
            containers.append(package_containers)

    if base_connector:
        base_connector.send_progress(" ")

    return containers
# -------- Stix -------

# -------- Taxii ------


def parse_taxii_message(taxii_message, base_connector=None):
    number_of_cbs = len(taxii_message.content_blocks)

    if not number_of_cbs:
        return {'error': 'no control blocks found'}

    packages = []

    for i, cb in enumerate(taxii_message.content_blocks):

        if base_connector:
            base_connector.send_progress("Parsing Content Block # {0}".format(i))

        # Give it to the stix parser to create the containers and artifacts
        # This code is the only place where the stix parsing will be written
        stix_xml = cb.content
        cstrio = StringIO()
        cstrio.write(stix_xml)
        cstrio.seek(0)

        package = parse_stix(cstrio, base_connector)

        if package:
            # print (json.dumps(package, indent=' ' * 4))
            packages.append(package)

    return parse_packages(packages, base_connector)

# -------- Taxii ------
