# mans_to_es
[![Version](https://img.shields.io/pypi/v/mans_to_es.svg)](https://pypi.python.org/pypi/mans_to_es)
[![GitHub license](https://img.shields.io/github/license/ldo-cert/mans_to_es.svg)](https://github.com/LDO-CERT/mans_to_es)
[![HitCount](http://hits.dwyl.com/LDO-CERT/mans_to_es.svg)](http://hits.dwyl.com/LDO-CERT/mans_to_es)

Parses the FireEye HX .mans triage collections and send them to ElasticSearch

## Table of Contents
1. [About](#about)
2. [Getting started](#getting-started)
3. [Contributing](#contributing)
4. [Disclaimer](#disclaimer)


## About
mans_to_es is an open source tool for parsing FireEye HX .mans triage collections and send them to ElasticSearch.

Mans file is a zipped collection of xml that we parse using [xmltodict](https://github.com/martinblech/xmltodict).
It uses pandas and multiprocessing to speed up the parsing with xml files.

## Getting started
#### Installation
```
pip install mans-to-es
```

#### Developing

If you want to develop with the script you can download and place it under /usr/local/bin and make it executable.

#### Usage as script

```
$ mans_to_es.py --help
usage: MANS to ES [-h] [--filename FILENAME] [--name NAME] [--index INDEX]
                  [--es_host ES_HOST] [--es_port ES_PORT]
                  [--cpu_count CPU_COUNT] [--bulk_size BULK_SIZE] [--version]

Push .mans information in Elasticsearch index

optional arguments:
  -h, --help            show this help message and exit
  --filename FILENAME   Path of the .mans file
  --name NAME           Timeline name
  --index INDEX         ES index name
  --es_host ES_HOST     ES host
  --es_port ES_PORT     ES port
  --cpu_count CPU_COUNT
                        cpu count
  --bulk_size BULK_SIZE
                        Bulk size for multiprocessing parsing and upload
  --version             show program's version number and exit

```

#### Usage as lib

```
>>> from mans_to_es import MansToEs
>>> a = MansToEs()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
TypeError: __init__() missing 5 required positional arguments: 'filename', 'index', 'name', 'es_host', and 'es_port'
>>> a = MansToEs(filename = '<file.mans>', index="<index>", name="<name>", es_host="localhost", es_port=9200)
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
