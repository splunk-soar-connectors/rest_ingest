# --
# File: rest_connector.py
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

import json
import imp
import os
from django.http import Http404

# Phantom imports
import phantom.app as phantom
from phantom.app import BaseConnector

from traceback import format_exc
import phantom_ui.ui.models as ph_models
import phantom_ui.ui.shared as ph_shared

import copy

INGEST_ERROR_CURRENTLY_DOES_NOT_SUPPORT_ACTIONS = "This connector does not support any actions."

MODULE_NAME = 'custom_parser'
HANDLER_NAME = 'handle_request'

my_json = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'rest_ingest.json')
my_json = json.loads(open(my_json).read())
connector_id = my_json['appid']

CANNED_SCRIPTS = {
  "STIX": "stix_rest_handler",
  "FireEye": "fireeye_rest_handler",
}


def handle_request(request, path_parts):
  # flake8: noqa
  if not path_parts:
    raise ph_shared.Http400('Incomplete path. No asset specified')
  asset_name = path_parts.pop(0)
  asset = ph_models.Asset.objects.filter(name=asset_name, disabled=False).first()  # pylint: disable=E1101
  if not asset:
    raise Http404('Asset "{}" not found'.format(asset_name))
  parse_script = asset.configuration.get('parse_script')
  try:
    handler_function = None
    if parse_script:
      mod = imp.new_module(MODULE_NAME)
      exec parse_script in mod.__dict__
      if not hasattr(mod, HANDLER_NAME):
        raise ph_shared.Http400('Parse script missing handler function "{}"'.format(HANDLER_NAME))
      handler_function = getattr(mod, HANDLER_NAME)
    else:
      parse_script = asset.configuration.get('stock_scripts')
      if parse_script in CANNED_SCRIPTS:

        # get the directory of the file
        dirpath = os.path.abspath(__file__).split('/')[-2]
        path = '{}.'.format(dirpath) + CANNED_SCRIPTS[parse_script]
        mod = __import__(path, globals(), locals(), [HANDLER_NAME], -1)
        handler_function = getattr(mod, HANDLER_NAME)
    if not handler_function:
      raise ph_shared.Http400('Asset "{}" has no attached parse handler'.format(asset_name))
    result = handler_function(request)

    if ((type(result) == str) or (type(result) == unicode)):
        # Error condition
        raise ph_shared.Http400('Parse script returned an error "{0}"'.format(result))

    if not hasattr(result, '__iter__'):
      raise ph_shared.Http400('Parse script returned an invalid response of type "{}"'.format(type(result)))
    response = {'success': False}
    response['messages'] = messages = []
    status_code = 200
    for r in result:
      if not hasattr(r, 'get'):
        raise ph_shared.Http400('Parse script returned an invalid response containing a(n) "{}" object'.format(type(r)))
      container = r.get('container')
      artifacts = r.get('artifacts')
      container_id = None
      if container and hasattr(container, '__setitem__'):
        container['asset_id'] = asset.id
        container['ingest_app_id'] = connector_id
        if not container.get('label'):
          container['label'] = asset.configuration.get('ingest', {}).get('container_label')
        try:
          cur_response = ph_models.Container.rest_create(container, request.user, request)
          response_json = json.loads(cur_response.content)
        except ph_shared.Http400 as e:
          if e.message.startswith('duplicate'):  # pylint: disable=E1101
            exc_json = json.loads(e.response.content)
            cur_response = ph_models.Container.rest_update(exc_json['existing_container_id'], container, None) # pylint: disable=E1101
            response_json = json.loads(cur_response.content)
          else:
            raise
        response_json['document'] = 'container'
        container_id = response_json.get('id')
        if not container_id:
          raise ph_shared.Http400('Unknown error when inserting container, no resulting container id. Response: {}'.format(response_json))
        messages.append(response_json)
        status_code = cur_response.status_code
      if artifacts and hasattr(artifacts, '__iter__'):
        for j, a in enumerate(artifacts):
          try:
            if ('source_data_identifier' not in a):
                a['source_data_identifier'] = j
            if not a.get('container_id'):
              a['container_id'] = container_id
            a['asset_id'] = asset.id
            a['ingest_app_id'] = connector_id
            if 'run_automation' not in a:
              if a == artifacts[-1]:
                a['run_automation'] = True
              else:
                a['run_automation'] = False

            cur_response = ph_models.Artifact.rest_create(copy.deepcopy(a), request.user, request)
            response_json = json.loads(cur_response.content)
            response_json['document'] = 'artifact'
            messages.append(response_json)
          except ph_shared.HttpError as e:
            if not e.message.endswith('already exists'):  # pylint: disable=E1101
              raise
            response_json = json.loads(e.response.content)
            messages.append(response_json)

    response['success'] = True
    return response

  except ph_shared.Http400 as e:
    raise
  except Http404 as e:
    raise
  except Exception as e:
    stack = format_exc()
    raise ph_shared.Http400(e.message, json_value={'stack': stack})


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
