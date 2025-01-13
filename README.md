[comment]: # "Auto-generated SOAR connector documentation"
# REST Data Source

Publisher: Splunk  
Connector Version: 2.0.11  
Product Vendor: Generic  
Product Name: REST Data Source  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.3.0  

This app implements custom REST handlers for external implementations to push ingest data such as events and artifacts into Phantom

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2025 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
This App is an Ingestion source. In the Phantom documentation, in the [Administration
Manual](../admin/) under the [Data Sources](../admin/sources) section, you will find an explanation
of how Ingest Apps works and how information is extracted from the ingested data. There is a general
explanation in Overview, and some individuals Apps have their own sections.

A video explaining the configuration of a REST Asset for ingestion can be found on the Phantom
portal at [this link](https://my.phantom.us/video/4)

## jsonpath_rw

This app makes use of the Python jsonpath_rw module, which is licensed under the Apache 2.0 License,
Copyright 2013- Kenneth Knowles

## weakrefmethod

This app makes use of the Python weakrefmethod module, which is licensed under the Python Software
Foundation License.

## cybox

This app makes use of the Python cybox module, which is licensed under the BSD License, Copyright
(c) 2017, The MITRE Corporation.

## decorator

This app makes use of the Python decorator module, which is licensed under the BSD License,
Copyright (c) 2005-2018, Michele Simionato.

## stix

This app makes use of the Python stix module, which is licensed under the BSD License, Copyright (c)
2017, The MITRE Corporation.

## six

This app makes use of the Python six module, which is licensed under the MIT License, Copyright (c)
2010-2020 Benjamin Peterson

## mixbox

This app makes use of the Python mixbox module, which is licensed under the BSD License, Copyright
(c) 2017, The MITRE Corporation.

## ordered_set

This app makes use of the Python ordered_set module, which is licensed under the MIT License,
Copyright (c) 2018 Luminoso Technologies, Inc.

## ply

This app makes use of the Python ply module, which is licensed under the BSD License, Copyright (C)
2001-2020 David M. Beazley (Dabeaz LLC).

## python_dateutil

This app makes use of the Python python_dateutil module, which is licensed under the Apache 2.0
License, Copyright 2017- Paul Ganssle

## libtaxii

This app makes use of the Python libtaxii module, which is licensed under the BSD License, Copyright
(c) 2017, The MITRE Corporation.


### Configuration variables
This table lists the configuration variables required to operate REST Data Source. These variables are specified when configuring a REST Data Source asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**parse_script** |  optional  | file | Custom Python REST handler
**stock_scripts** |  optional  | string | Preconfigured parsing scripts