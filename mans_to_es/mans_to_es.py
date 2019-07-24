#!/usr/bin/env python3

import sys
import os
import json
import zipfile
import xmltodict
import collections
import datetime
import pandas as pd
import argparse
import logging
from multiprocessing import cpu_count, Pool
from elasticsearch import helpers, Elasticsearch

# hide ES log
es_logger = logging.getLogger("elasticsearch")
es_logger.setLevel(logging.ERROR)
url_logger = logging.getLogger("urllib3")
url_logger.setLevel(logging.ERROR)

FORMAT = "%(asctime)-15s %(message)s"
logging.basicConfig(filename="mans_to_es.log", level=logging.DEBUG, format=FORMAT)

type_name = {
    "persistence": {
        "key": "PersistenceItem",
        "datefield": [
            "RegModified",
            "FileCreated",
            "FileModified",
            "FileAccessed",
            "FileChanged",
        ],
        "message_fields": [
            ["RegPath"],
            ["FilePath"],
            ["FilePath"],
            ["FilePath"],
            ["FilePath"],
        ],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
    },
    "processes-memory": {  ## OK
        "key": "ProcessItem",
        "datefield": ["startTime"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": [["name"]],
    },
    "urlhistory": {  ## OK
        "key": "UrlHistoryItem",
        "datefield": ["LastVisitDate"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": [["URL"]],
    },
    "stateagentinspector": {  ## OK
        "key": "eventItem",
        "datefield": ["timestamp"],
        "dateformat": "%Y-%m-%dT%H:%M:%S.%fZ",
        "subtypes": {
            "addressNotificationEvent": {
                "meta": ["message", "address", "datetime", "timestamp_desc"],
                "message_fields": ["address"],
            },
            "regKeyEvent": {
                "meta": [
                    "message",
                    "hive",
                    "keyPath",
                    "path",
                    "pid",
                    "process",
                    "processPath",
                    "username",
                    "datetime",
                    "timestamp_desc",
                ],
                "message_fields": ["keyPath"],
            },
            "ipv4NetworkEvent": {
                "meta": [
                    "message",
                    "localIP",
                    "localPort",
                    "pid",
                    "process",
                    "processPath",
                    "protocol",
                    "remoteIP",
                    "remotePort",
                    "username",
                    "datetime",
                    "timestamp_desc",
                ],
                "message_fields": ["localIP", "remoteIP"],
                "hits_key": "EXC",
            },
            "processEvent": {
                "meta": [
                    "message",
                    "md5",
                    "parentPid",
                    "parentProcess",
                    "parentProcessPath",
                    "pid",
                    "process",
                    "processCmdLine",
                    "processPath",
                    "startTime",
                    "username",
                    "datetime",
                    "timestamp_desc",
                    "eventType",
                ],
                "message_fields": ["process", "eventType"],
                "hits_key": "EXC",
            },
            "imageLoadEvent": {
                "meta": [
                    "devicePath",
                    "drive",
                    "message",
                    "fileExtension",
                    "fileName",
                    "filePath",
                    "fullPath",
                    "pid",
                    "process",
                    "processPath",
                    "username",
                    "datetime",
                    "timestamp_desc",
                ],
                "message_fields": ["fileName"],
            },
            "fileWriteEvent": {
                "meta": [
                    "closed",
                    "dataAtLowestOffset",
                    "devicePath",
                    "drive",
                    "message",
                    "fileExtension",
                    "fileName",
                    "filePath",
                    "fullPath",
                    "lowestFileOffsetSeen",
                    "md5",
                    "numBytesSeenWritten",
                    "pid",
                    "process",
                    "processPath",
                    "size",
                    "textAtLowestOffset",
                    "username",
                    "writes",
                    "datetime",
                    "timestamp_desc",
                ],
                "message_fields": ["fileName"],
                "hits_key": "PRE",
            },
            "dnsLookupEvent": {
                "meta": [
                    "message",
                    "hostname",
                    "pid",
                    "process",
                    "processPath",
                    "username",
                    "datetime",
                    "timestamp_desc",
                ],
                "message_fields": ["hostname"],
            },
            "urlMonitorEvent": {
                "meta": [
                    "message",
                    "hostname",
                    "requestUrl",
                    "urlMethod",
                    "userAgent",
                    "httpHeader",
                    "remoteIpAddress",
                    "remotePort",
                    "localPort",
                    "pid",
                    "process",
                    "processPath",
                    "username",
                    "datetime",
                    "timestamp_desc",
                ],
                "message_fields": ["requestUrl"],
            },
        },
    },
    "prefetch": {  ## OK
        "key": "PrefetchItem",
        "datefield": ["LastRun", "Created"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": [["ApplicationFileName"], ["ApplicationFileName"]],
    },
    "filedownloadhistory": {  ## OK
        "key": "FileDownloadHistoryItem",
        "datefield": ["LastModifiedDate"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": [["SourceURL"]],
    },
    "tasks": {"key": "TaskItem", "skip": True},
    "ports": {"key": "PortItem", "skip": True},
    "useraccounts": {"key": "UserItem", "skip": True},
    "disks": {"key": "DiskItem", "skip": True},
    "volumes": {"key": "VolumeItem", "skip": True},
    "network-dns": {"key": "DnsEntryItem", "skip": True},
    "network-route": {"key": "RouteEntryItem", "skip": True},
    "network-arp": {"key": "ArpEntryItem", "skip": True},
    "sysinfo": {"skip": True, "key": "SystemInfoItem"},
    "registry-raw": {"key": "RegistryItem", "skip": True},
    "services": {"key": "ServiceItem", "skip": True},
}


def output_dict(details, itemtype):
    """
        Output_dict: details column in stateagentinspector df contains all the row info
        In:
            row: row of stateagentinspector file [could be a dict or a list of dict]
            itemtype: stateagentinspector subtype
        Out:
            the details dict exploded in multiple columns
    """
    detail = details.get("detail", [])
    ret_value = {}

    if type(detail) in (collections.OrderedDict, dict):
        ret_value[detail["name"]] = detail["value"]
    elif type(detail) == list:
        for i in detail:
            ret_value[i["name"]] = i["value"]
    return pd.Series(ret_value)


def convert_date(argument, date_format="%Y-%m-%dT%H:%M:%S.%fZ"):
    """
        convert_date: parse date field and convert to es format
        in:
            argument: object to parse
            date_format: format of the argument field
        out:
            parsed data
    """
    try:
        d = datetime.datetime.strptime(argument, date_format)
        iso_date = d.isoformat(timespec="seconds")
        iso_date_new = iso_date + "+00:00"
        return iso_date_new
    except TypeError:
        return None


class MansToEs:
    def __init__(self, args):
        self.filename = args.filename
        self.index = args.index
        self.name = args.name
        self.bulk_size = args.bulk_size
        self.cpu_count = args.cpu_count
        self.es_info = {"host": args.es_host, "port": args.es_port}
        self.folder_path = self.filename + "__tmp"
        self.filelist = {}
        self.ioc_alerts = {}
        self.exd_alerts = []

        logging.debug(
            "Start parsing %s. Push on %s index and %s timeline"
            % (args.filename, args.name, args.index)
        )

    def get_hits(self):
        """
            Get hit and alert from hits.json file
        """
        with open(os.path.join(self.folder_path, "hits.json"), "r") as f:
            for x in json.load(f):
                if x.get("data", {}).get("key", None):
                    self.ioc_alerts.setdefault(
                        x["data"]["key"]["event_type"], []
                    ).append(x["data"]["key"]["event_id"])
                elif x.get("data", {}).get("documents", None):
                    self.exd_alerts.append(
                        {
                            "source": x["source"],
                            "resolution": x["resolution"],
                            "process id": x["data"]["process_id"],
                            "process name": x["data"]["process_name"],
                            "alert_code": "XPL",
                            "datetime": convert_date(
                                x["data"]["earliest_detection_time"],
                                date_format="%Y-%m-%dT%H:%M:%SZ",
                            ),
                            "ALERT": True,
                            "message": "PID: %d PROCESS: %s"
                            % (x["data"]["process_id"], x["data"]["process_name"]),
                        }
                    )
        if len(self.exd_alerts) > 0:
            es = Elasticsearch([self.es_info])
            helpers.bulk(
                es, self.exd_alerts, index=self.index, doc_type="generic_event"
            )
        logging.debug("alert collected")

    def extract_mans(self):
        """
            Unzip .mans file
        """
        zip_ref = zipfile.ZipFile(self.filename, "r")
        zip_ref.extractall(self.folder_path)
        zip_ref.close()
        logging.debug("File extracted in %s" % self.folder_path)

    def parse_manifest(self):
        """
            Obtains filenames from manifest.json file in extracted foldere
        """
        with open(os.path.join(self.folder_path, "manifest.json"), "r") as f:
            data = json.load(f)
            for item in data["audits"]:
                if item["generator"] not in self.filelist.keys():
                    self.filelist[item["generator"]] = []
                for res in item["results"]:
                    if res["type"] == "application/xml":
                        self.filelist[item["generator"]].append(res["payload"])
        logging.debug("Manifest.json parsed")

    def process(self):
        """
            Process all files contained in .mans extracted folder
        """
        for filetype in self.filelist.keys():

            # Ignore items if not related to timeline
            # TODO: will use them in neo4j for relationship
            if type_name[filetype].get("skip", False):
                logging.debug("Filetype: %s - SKIPPED" % type_name[filetype]["key"])
                continue
            logging.debug("Filetype: %s - START" % type_name[filetype]["key"])

            # Read all files related to the type
            for file in self.filelist[filetype]:

                # logging.debug("Opening %s [%s]" % (file, filetype))

                with open(os.path.join(self.folder_path, file), "r") as f:
                    df_xml = (
                        xmltodict.parse(f.read())
                        .get("itemList", {})
                        .get(type_name[filetype]["key"], {})
                    )
                    if df_xml == {}:
                        logging.debug("\tEmpty file")
                        continue
                    df = pd.DataFrame(df_xml)

                # if not valid date field drop them
                df = df.dropna(
                    axis=0, how="all", subset=type_name[filetype]["datefield"]
                )

                # stateagentinspector have in eventType the main subtype and in timestamp usually the relative time
                if filetype == "stateagentinspector":
                    df = df.rename(columns={"eventType": "message"})
                    df["datetime"] = df[type_name[filetype]["datefield"]]
                else:
                    df["message"] = filetype
                    # convert all export date fields to default format
                    for datefield in type_name[filetype]["datefield"]:
                        df[datefield] = df[datefield].apply(
                            lambda x: convert_date(x, type_name[filetype]["dateformat"])
                        )
                df = df.drop(
                    ["@created", "@sequence_num", "timestamp"],  # "@uid",
                    axis=1,
                    errors="ignore",
                )
                logging.debug("\tPreprocessing done")

                # stateagentinspector is big and converted in parallel
                if filetype == "stateagentinspector":
                    pieces = []

                    for itemtype in [x for x in type_name[filetype]["subtypes"].keys()]:
                        tmp_df = df[df.message == itemtype].reset_index()
                        for i in range(0, len(tmp_df), self.bulk_size):
                            pieces.append(
                                (tmp_df.loc[i : i + self.bulk_size - 1, :], itemtype)
                            )
                    with Pool(processes=self.cpu_count) as pool:
                        pool.starmap_async(
                            self.explode_stateagentinspector, pieces
                        ).get()
                else:
                    # explode if multiple date
                    list_dd = []
                    df_dd = pd.DataFrame()
                    df_tmp = df[
                        [
                            x
                            for x in df.columns
                            if x not in type_name[filetype]["datefield"]
                        ]
                    ]
                    for index, x in enumerate(type_name[filetype]["datefield"]):
                        df_tmp2 = df_tmp.copy()
                        df_tmp2["datetime"] = df[[x]]
                        if type_name[filetype].get("message_fields", None):
                            for mf in type_name[filetype]["message_fields"][index]:
                                df_tmp2["message"] += " - " + df_tmp2[mf]
                        df_tmp2["message"] += " [%s]" % x
                        df_tmp2 = df_tmp2[df_tmp2["datetime"].notnull()]
                        list_dd.append(df_tmp2)
                    df_dd = pd.concat(list_dd, sort=False)

                    df_dd["timestamp_desc"] = df_dd["message"]
                    self.to_elastic(df_dd)
                logging.debug("\tUpload done")
        logging.debug("completed")

    def explode_stateagentinspector(self, edf, itemtype):
        """
            explode_stateagentinspector: parse stateagentinspector file
            In: 
                edf: piece of stateagentinspector file
                itemtype: subtype of processes piece
        """
        end = pd.concat(
            [
                edf,
                edf.apply(
                    lambda row: output_dict(row.details, itemtype),
                    axis=1,
                    result_type="expand",
                ),
            ],
            axis=1,
        )

        end[["source", "resolution", "ALERT", "alert_code"]] = end["@uid"].apply(
            lambda x: pd.Series(
                {
                    "source": "IOC",
                    "resolution": "ALERT",
                    "ALERT": True,
                    "alert_code": type_name["stateagentinspector"]["subtypes"][
                        itemtype
                    ].get("hits_key", None),
                }
            )
            if itemtype in self.ioc_alerts.keys()
            and int(x) in self.ioc_alerts[itemtype]
            else pd.Series(
                {"source": None, "resolution": None, "ALERT": None, "alert_code": None}
            )
        )

        end = end.drop(["details"], axis=1, errors="ignore")
        if type_name["stateagentinspector"]["subtypes"][itemtype].get(
            "message_fields", None
        ):
            for mf in type_name["stateagentinspector"]["subtypes"][itemtype][
                "message_fields"
            ]:
                end["message"] += " - " + end[mf]
        end["timestamp_desc"] = end["message"]
        self.to_elastic(end)
        logging.debug("\t\tUpload part - done")

    def to_elastic(self, end):
        """
            to_elastic: push dataframe to elastic index
            In:
                end: dataframe to push
        """
        es = Elasticsearch([self.es_info])
        data = end.to_json(orient="records")
        data = json.loads(data)
        helpers.bulk(es, data, index=self.index, doc_type="generic_event")


def Main():
    parser = argparse.ArgumentParser(
        description="Push .mans information in Elasticsearch index", prog="MANS to ES"
    )
    # Required parameters
    parser.add_argument("--filename", dest="filename", help="Path of the .mans file")
    parser.add_argument("--name", dest="name", help="Timeline name")
    parser.add_argument("--index", dest="index", help="ES index name")
    parser.add_argument("--es_host", dest="es_host", help="ES host")
    parser.add_argument("--es_port", dest="es_port", help="ES port")

    # Optional parameters to increase performances
    parser.add_argument(
        "--cpu_count",
        dest="cpu_count",
        default=cpu_count() - 1,
        help="cpu count",
        type=int,
    )
    parser.add_argument(
        "--bulk_size",
        dest="bulk_size",
        default=1000,
        help="Bulk size for multiprocessing parsing and upload",
        type=int,
    )

    parser.add_argument(
        "--version", dest="version", action="version", version="%(prog)s 1.0"
    )
    args = parser.parse_args()

    if not all([args.name, args.index, args.es_port, args.es_host]):
        parser.print_usage()
    else:
        try:
            mte = MansToEs(args)
            mte.extract_mans()
            mte.parse_manifest()
            mte.get_hits()
            mte.process()
        except:
            logging.exception("Error parsing .mans")
            return False
    return True


if __name__ == "__main__":
    if not Main():
        sys.exit(1)
    else:
        sys.exit(0)
