# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from unittest.mock import Mock

import pytest  # pylint: disable=import-error
from django.http import Http404

import rest_connector


def test_handle_request_filters_asset_by_rest_data_source_app(monkeypatch):
    request = Mock()
    response = Mock()
    response.json.return_value = {"count": 0, "data": []}
    call_rest_api = Mock(return_value=response)
    monkeypatch.setattr(rest_connector, "_call_phantom_rest_api", call_rest_api)

    with pytest.raises(Http404):
        rest_connector.handle_request(request, ["carrier_asset"])

    call_rest_api.assert_called_once_with(
        request,
        "asset",
        "get",
        params={
            "_filter_name": '"carrier_asset"',
            "_filter_disabled": '"False"',
            "_filter_app__appid": f'"{rest_connector.connector_id}"',
        },
    )
