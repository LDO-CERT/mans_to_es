# mans_to_es
[![Version](https://img.shields.io/pypi/v/mans_to_es.svg)](https://pypi.python.org/pypi/mans_to_es)
[![GitHub license](https://img.shields.io/github/license/ldo-cert/mans_to_es.svg)](https://github.com/LDO-CERT/mans_to_es)
<!-- [![HitCount](http://hits.dwyl.com/LDO-CERT/mans_to_es.svg)](http://hits.dwyl.com/LDO-CERT/mans_to_es) -->

Parses the FireEye HX .mans triage collections and send them to ElasticSearch

## Table of Contents
- [mans_to_es](#mans_to_es)
  - [Table of Contents](#table-of-contents)
  - [About](#about)
  - [Getting started](#getting-started)
    - [Installation](#installation)
    - [Develop](#develop)
  - [Usage as script](#usage-as-script)
    - [TIMESKETCH](#timesketch)
      - [EXAMPLES](#examples)
      - [FIRST RUN](#first-run)
    - [ELASTIC](#elastic)
      - [EXAMPLES](#examples-1)
  - [Usage as lib](#usage-as-lib)
  - [Contributing](#contributing)
  - [Disclaimer](#disclaimer)

## About
mans_to_es is an open source tool for parsing FireEye HX .mans triage collections and send them to ElasticSearch.<br>
Mans file is a zipped collection of xml that we parse using [xmltodict](https://github.com/martinblech/xmltodict).<br>
It uses pandas and multiprocessing to speed up the parsing with xml files.

## Getting started
### Installation
```
pip install mans-to-es
```

### Develop

You can clone this repo or download directly the mans_to_es.py script, place it under /usr/local/bin and make it executable.

## Usage as script

```
>>> mans_to_es.py --help
usage: MANS to ES [-h] --filename FILENAME [--cpu_count CPU_COUNT] [--bulk_size BULK_SIZE] [--version] {elastic,timesketch} ...

Push .mans information in ElasticSearch index

positional arguments:
  {elastic,timesketch}
    elastic             Save data in elastic
    timesketch          Save data in TimeSketch

optional arguments:
  -h, --help            show this help message and exit
  --filename FILENAME   Path of the .mans file
  --cpu_count CPU_COUNT
                        cpu count
  --bulk_size BULK_SIZE
                        Bulk size for multiprocessing parsing and upload
  --version             show program's version number and exit
```

### TIMESKETCH
```
>>> mans_to_es.py timesketch --help
usage: MANS to ES timesketch [-h] [--sketch_id SKETCH_ID] [--sketch_name SKETCH_NAME] [--sketch_description SKETCH_DESCRIPTION] [--timeline_name TIMELINE_NAME]

optional arguments:
  -h, --help            show this help message and exit
  --sketch_id SKETCH_ID
                        TimeSketch Sketch id
  --sketch_name SKETCH_NAME
                        TimeSketch Sketch name
  --sketch_description SKETCH_DESCRIPTION
                        TimeSketch Sketch description
  --timeline_name TIMELINE_NAME
                        TimeSketch Timeline Name
```

#### EXAMPLES
```
>>> mans_to_es.py --filename test_file.mans timesketch --sketch_name test_file --timeline_name test_file
>>> mans_to_es.py --filename test_file.mans timesketch --sketch_id 1
```

#### FIRST RUN
During the first run the script will ask some information to connect to your timesketch instance.<br>
A configuration files is created in your home directory for subsequent runs.

```
>>> mans_to_es.py --filename file.mans test_file --sketch_name test_file --timeline_name test_file
What is the value for <host_uri> (URL of the Timesketch server): http://localhost:5000
What is the value for <auth_mode> (Authentication mode, valid choices are: "userpass" (user/pass) or "oauth"): userpass
What is the value for <username> (The username of the Timesketch user): dev
Password for user dev [**] 
```

### ELASTIC
```
>>> mans_to_es.py elastic --help
usage: MANS to ES elastic [-h] [--index INDEX] [--es_host ES_HOST] [--es_port ES_PORT]

optional arguments:
  -h, --help         show this help message and exit
  --index INDEX      ElasticSearch Index name
  --es_host ES_HOST  ElasticSearch host
  --es_port ES_PORT  ElasticSearch port
```

#### EXAMPLES
```
>>> mans_to_es.py --filename timeline.mans elastic --index all_in --es_host localhost --es_port 9200
```

## Usage as lib
```
>>> from mans_to_es import MansToEs
>>>
>>> # PUSHING TO ELASTIC
>>> a = MansToEs(mode = 'elastic', filename = '<file.mans>', index="<index>", es_host="localhost", es_port=9200)
>>> a.run()
>>>
>>> # PUSHING TO EXISTING TIMESKETCH INDEX
>>> a = MansToEs(mode = 'timesketch', filename = '<file.mans>', sketch_id=<sketch_id>, timeline_name='<timeline_name>')
>>> a.run()
>>>
>>> # PUSHING TO A NEW TIMESKETCH INDEX
>>> a = MansToEs(mode = 'timesketch', filename = '<file.mans>', sketch_name='<sketch_name>', timeline_name='<timeline_name>')
>>> a.run()
```

## Contributing

**If you want to contribute to mans_to_es, be sure to review the [contributing guidelines](CONTRIBUTING.md). This project adheres to mans_to_es
[code of conduct](CODE_OF_CONDUCT.md). By participating, you are expected to
uphold this code.**

**We use [GitHub issues](https://github.com/LDO-CERT/mans_to_es/issues) for
tracking requests and bugs.

## Disclaimer
This is not an official FireEye product. Bugs are expected. 
