# File: rest_connector.py
#
# Copyright (c) 2016-2023 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
import base64
import copy
import imp
import importlib
import json
import logging
import os
import re
from traceback import format_exc

import encryption_helper
# Phantom imports
import phantom.app as phantom
import requests
import six
from django.http import Http404, HttpResponse, JsonResponse
from phantom.app import BaseConnector
from phantom_common.compat import convert_to_unicode
from phantom_common.install_info import get_rest_base_url

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

def _get_creds_from_request(request):
    """
    Attempt to get a username and/or password/token out of a request

    This function was copied, as is, from www/phantom_ui/ui/rest.py
    in order to avoid making platform changes during a patch.

    TODO: the original function should be moved into pycommon and this app
    should call that function

    Args:
        request: A WSGIRequest object.

    Returns:
        username, password: Either are either strings or None
    """
    username, password = None, None
    prefix = 'Basic '
    http_auth = request.META.get('HTTP_AUTHORIZATION', '')

    if http_auth.startswith(prefix):
        creds = base64.b64decode(http_auth[len(prefix):]).decode()  # decode and convert to a string

        # The basic auth header should be encrypted if it starts with enc_ and ends with _enc

        enc_creds = re.match(r'^enc_(.+)_enc$', creds)
        if enc_creds:
            enc_creds = enc_creds.group(1)
            # Encrypted basic auth headers prepend an 8 char salt
            creds = encryption_helper.decrypt(enc_creds[8:], enc_creds[:8])

        # Raises a ValueError if basic auth holds a token
        try:
            username, password = creds.split(':', 1)
        except ValueError:
            password = creds

    # If we didn't get a username or a password yet, it must be token auth
    if not (username or password):
        password = request.META.get('HTTP_PH_AUTH_TOKEN')

    return username, password


def _call_phantom_rest_api(request, url, method, **kwargs):
    """Make a request to phantom rest api"""
    fn = getattr(requests, method)
    url = os.path.join(REST_BASE_URL, url)

    headers = kwargs.get('headers', {})
    username, password = _get_creds_from_request(request)

    # Authenticate with basic auth
    if username and password:
        kwargs['auth'] = (username, password)

    # Authenticate using a token
    elif password and not username:
        headers.setdefault('ph-auth-token', password)

    return fn(url, headers=headers, verify=False, **kwargs)

def _quote_wrap(value):
    """Wrap a value in quotes."""
    return '"{}"'.format(value)


def handle_request(request, path_parts):
    # flake8: noqa
    if not path_parts:
        return HttpResponse('Incomplete path. No asset specified', status=400)   # nosemgrep

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
                return HttpResponse(error, status=400)   # nosemgrep
            handler_function = getattr(mod, HANDLER_NAME)

        else:

            parse_script = asset['configuration'].get('stock_scripts')
            logger.debug('Using stock script: {}'.format(parse_script))
            if parse_script in CANNED_SCRIPTS:
                # get the directory of the file
                path = CANNED_SCRIPTS[parse_script]
                mod = __import__(path, globals(), locals(), [HANDLER_NAME], -1 if six.PY2 else 0)
                handler_function = getattr(mod, HANDLER_NAME)

        if not handler_function:
            return HttpResponse('Asset "{}" has no attached parse handler'.format(asset_name), status=400)   # nosemgrep

        result = handler_function(request)

        if isinstance(result, six.string_types):
            # Error condition
            return HttpResponse('Parse script returned an error "{0}"'.format(result), status=400)   # nosemgrep

        if not hasattr(result, '__iter__'):
            return HttpResponse(
                'Parse script returned an invalid response of type "{}"'.format(
                    type(result)),
                status=400
            )   # nosemgrep

        messages = []

        for r in result:
            if not hasattr(r, 'get'):
                return HttpResponse(
                    'Parse script returned an invalid response containing a(n) "{}" object'.format(
                        type(r)),
                  status=400
                )   # nosemgrep

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
                        status=400)   # nosemgrep

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
                        if artifact == artifacts[-1]:
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
                            status=400)   # nosemgrep

        return JsonResponse({
            'success': True,
            'messages': messages
        })

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
        return JsonResponse(response, status=400)


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
