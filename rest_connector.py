# File: rest_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
import json
import imp
import importlib
import os
import requests
import copy
from traceback import format_exc
import logging
import six

from django.http import Http404, HttpResponse

# Phantom imports
import phantom.app as phantom
from phantom.app import BaseConnector
from phantom_common.install_info import get_rest_base_url
from phantom_common.compat import convert_to_unicode


logger = logging.getLogger(__name__)

REST_BASE_URL = get_rest_base_url()
INGEST_ERROR_CURRENTLY_DOES_NOT_SUPPORT_ACTIONS = "This connector does not support any actions."
MODULE_NAME = 'custom_parser'
HANDLER_NAME = 'handle_request'

my_json = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'rest_ingest.json')
my_json = json.loads(open(my_json).read())
connector_id = my_json['appid']

CANNED_SCRIPTS = {
    "STIX": "parsers.stix_rest_handler",
    "FireEye": "parsers.fireeye_rest_handler",
}

def _get_auth_token_from_request(request):
    """Parse authentication information from request headers.

    We can use it to make calls to the phantom rest api.
    """
    auth_token = request.META.get('HTTP_PH_AUTH_TOKEN')
    if not auth_token:
        raise Exception('Invalid request. Please use "ph-auth-token" to authenticate the request')

    return auth_token

def _call_phantom_rest_api(request, url, method, **kwargs):
    """Make a request to phantom rest api"""
    fn = getattr(requests, method)
    url = os.path.join(REST_BASE_URL, url)
    headers = {'ph-auth-token': _get_auth_token_from_request(request)}

    return fn(url, headers=headers, verify=False, **kwargs)

def _quote_wrap(value):
    """Wrap a value in quotes."""
    return '"{}"'.format(value)


def handle_request(request, path_parts):
    # flake8: noqa
    if not path_parts:
        return HttpResponse('Incomplete path. No asset specified', status=400)

    asset_name = path_parts.pop(0)
    response = _call_phantom_rest_api(
        request,
        'asset',
        'get',
        params={'_filter_name': _quote_wrap(asset_name), '_filter_disabled': _quote_wrap(False)}
    )
    response_json = response.json()
    if int(response_json.get('count', 0)) == 0:
        raise Http404('Asset "{}" not found'.format(asset_name))

    asset = response_json['data'][0]
    logger.debug('Got asset: {}'.format(asset))

    parse_script = asset['configuration'].get('parse_script')

    try:
        handler_function = None
        if parse_script:
            logger.debug('Trying to exec custom script')
            # TODO: imp is deprecated since python 3.4. Switch to importlib.util.spec_from_loader /
            # TODO: importlib.util.module_from_spec, after dropping py2 support.
            mod = imp.new_module(MODULE_NAME)
            exec(parse_script, mod.__dict__)
            if not hasattr(mod, HANDLER_NAME):
                error = 'Parse script missing handler function "{}"'.format(HANDLER_NAME)
                logger.error(error)
                return HttpResponse(error, status=400)
            handler_function = getattr(mod, HANDLER_NAME)

        else:

            parse_script = asset['configuration'].get('stock_scripts')
            logger.debug('Using stock script: {}'.format(parse_script))
            if parse_script in CANNED_SCRIPTS:
                # get the directory of the file
                dirpath = os.path.abspath(__file__).split('/')[-2]
                path = '{}.'.format(dirpath) + CANNED_SCRIPTS[parse_script]
                mod = __import__(path, globals(), locals(), [HANDLER_NAME], -1)
                handler_function = getattr(mod, HANDLER_NAME)

        if not handler_function:
            return HttpResponse('Asset "{}" has no attached parse handler'.format(asset_name), status=400)

        result = handler_function(request)

        if isinstance(result, six.string_types):
            # Error condition
            return HttpResponse('Parse script returned an error "{0}"'.format(result), status=400)

        if not hasattr(result, '__iter__'):
            return HttpResponse(
                'Parse script returned an invalid response of type "{}"'.format(
                    type(result)),
                status=400
            )

        messages = []

        for r in result:
            if not hasattr(r, 'get'):
                return HttpResponse(
                    'Parse script returned an invalid response containing a(n) "{}" object'.format(
                        type(r)),
                  status=400
                )

            container = r.get('container')
            artifacts = r.get('artifacts')
            container_id = None

            if container and hasattr(container, '__setitem__'):
                container['asset_id'] = asset['id']
                container['ingest_app_id'] = connector_id

                if not container.get('label'):
                    container['label'] = asset['configuration'].get('ingest', {}).get('container_label', '')

                response = _call_phantom_rest_api(request, 'container', 'post', json=container)
                response_json = response.json()

                if response_json.get('success', False) is False and response_json.get('message', '').startswith('duplicate'):
                    response = _call_phantom_rest_api(
                        request,
                        os.path.join('container', str(response_json['existing_container_id'])),
                        'post',
                        json=container
                    )
                    response_json = response.json()

                container_id = response_json.get('id')
                if not container_id:
                    return HttpResponse(
                        'Unknown error when inserting container, no resulting container id. Response: {}'.format(
                            response_json),
                        status=400)

                response_json['document'] = 'container'
                messages.append(response_json)

            if artifacts and hasattr(artifacts, '__iter__'):
                for j, artifact in enumerate(artifacts):
                    if 'source_data_identifier' not in artifact:
                        artifact['source_data_identifier'] = j

                    if not artifact.get('container_id'):
                        artifact['container_id'] = container_id

                    artifact['asset_id'] = asset['id']
                    artifact['ingest_app_id'] = connector_id

                    if 'run_automation' not in artifact:
                        if a == artifacts[-1]:
                            artifact['run_automation'] = True
                        else:
                            artifact['run_automation'] = False

                    response = _call_phantom_rest_api(request, 'artifact', 'post', json=artifact)
                    response_json = response.json()

                    if response_json.get('success', False) is True:
                        response_json['document'] = 'artifact'
                        messages.append(response_json)

                    elif response_json.get('message', '').endswith('already exists'):
                        messages.append(response_json)

                    else:
                        return HttpResponse(
                            'Unknown error when inserting artifact. Response: {}'.format(response_json),
                            status=400)

        return HttpResponse(json.dumps({
            'success': True,
            'messages': messages
        }))

    except Http404 as e:
        raise

    except Exception as e:
        logger.error(e, exc_info=True)
        stack = format_exc()
        response = {
            'failed': True,
            'message': convert_to_unicode(e),
            'stack': stack
        }
        return HttpResponse(json.dumps(response), status=400)


class IngestConnector(BaseConnector):

    def __init__(self):
        # Call the BaseConnectors init first
        super(IngestConnector, self).__init__()

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        self.set_status(phantom.APP_ERROR, INGEST_ERROR_CURRENTLY_DOES_NOT_SUPPORT_ACTIONS)

        return self.get_status()
