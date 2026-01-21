This app is a data ingestion source for Splunk SOAR. Unlike typical SOAR apps that perform actions (like blocking IPs or quarantining endpoints), this app allows external systems to push security event data into SOAR in real-time via REST endpoints.

When data is received, the app parses it into SOAR containers (security events) and artifacts (observables like IPs, file hashes, domains). These containers and artifacts can then trigger automated playbooks and response workflows in SOAR.

This app supports two parsing options:

- **Stock Scripts**: Pre-built parsers for STIX 1.2 and FireEye alert formats
- **Custom Scripts**: Upload your own Python script to parse any data format

For details on writing custom parser scripts for this app, see [Using custom scripts with the Splunk SOAR REST API](https://help.splunk.com/en/splunk-soar/soar-cloud/rest-api-reference/using-the-splunk-soar-rest-api/use-a-custom-script)

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
