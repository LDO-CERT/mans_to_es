#!/usr/bin/env python3
import os, sys
import argparse
import collections
import json
import logging

import zipfile
import shutil

import datetime
import ciso8601

import xmltodict

import pandas as pd

from multiprocessing import Pool, cpu_count

import elasticsearch
from elasticsearch import helpers, Elasticsearch

from glob import glob

# hide ES log
es_logger = logging.getLogger("elasticsearch")
es_logger.setLevel(logging.ERROR)
url_logger = logging.getLogger("urllib3")
url_logger.setLevel(logging.ERROR)
pd.options.mode.chained_assignment = None

FORMAT = "%(asctime)-15s %(message)s"
logging.basicConfig(filename="mans_to_es.log", level=logging.DEBUG, format=FORMAT)

MANS_FIELDS = {
    "persistence": {
        "key": "PersistenceItem",
        "datefields": [
            "RegModified",
            "FileCreated",
            "FileModified",
            "FileAccessed",
            "FileChanged",
        ],
        "message_fields": {
            "RegModified": ["RegPath"],
            "FileCreated": ["FilePath"],
            "FileModified": ["FilePath"],
            "FileAccessed": ["FilePath"],
            "FileChanged": ["FilePath"],
        },
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
    },
    "processes-api": {
        "key": "ProcessItem",
        "datefields": ["startTime"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {"startTime": ["name"]},
    },
    "processes-memory": {
        "key": "ProcessItem",
        "datefields": ["startTime"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {"startTime": ["name"]},
    },
    "urlhistory": {
        "key": "UrlHistoryItem",
        "datefields": ["LastVisitDate"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {"LastVisitDate": ["URL"]},
    },
    "stateagentinspector": {
        "key": "eventItem",
        "datefields": ["timestamp"],
        "dateformat": "%Y-%m-%dT%H:%M:%S.%fZ",
        "SubEventType": {
            "addressNotificationEvent": {"message_fields": ["address"]},
            "regKeyEvent": {"message_fields": ["keyPath"]},
            "ipv4NetworkEvent": {
                "message_fields": ["localIP", "remoteIP"],
                "hits_key": "EXC",
            },
            "processEvent": {
                "message_fields": ["process", "eventType"],
                "hits_key": "EXC",
            },
            "imageLoadEvent": {"message_fields": ["fileName"]},
            "fileWriteEvent": {"message_fields": ["fileName"], "hits_key": "PRE"},
            "dnsLookupEvent": {
                "meta": ["hostname", "pid", "process", "processPath", "username"],
                "message_fields": ["hostname"],
            },
            "urlMonitorEvent": {"message_fields": ["requestUrl"]},
        },
    },
    "prefetch": {
        "key": "PrefetchItem",
        "datefields": ["LastRun", "Created"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {
            "LastRun": ["ApplicationFileName"],
            "Created": ["ApplicationFileName"],
        },
    },
    "filedownloadhistory": {
        "key": "FileDownloadHistoryItem",
        "datefields": ["LastModifiedDate", "LastAccessedDate", "StartDate", "EndDate"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {
            "LastModifiedDate": ["SourceURL"],
            "LastAccessedDate": ["SourceURL"],
            "StartDate": ["SourceURL"],
            "EndDate": ["SourceURL"],
        },
    },
    "files-raw": {
        "key": "FileItem",
        "datefields": ["Created", "Modified", "Accessed", "Changed"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {
            "Created": ["FullPath"],
            "Modified": ["FullPath"],
            "Accessed": ["FullPath"],
            "Changed": ["FullPath"],
        },
    },
    "cookiehistory": {
        "key": "CookieHistoryItem",
        "datefields": ["LastAccessedDate", "ExpirationDate"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {
            "LastAccessedDate": ["HostName"],
            "ExpirationDate": ["HostName"],
        },
    },
    "eventlogs": {
        "key": "EventLogItem",
        "datefields": ["genTime"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {"genTime": ["EID", "source", "type"]},
    },
    "registry-raw": {
        "key": "RegistryItem",
        "datefields": ["Modified"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {"Modified": ["KeyPath"]},
    },
    "tasks": {"key": "TaskItem", "skip": True},
    "ports": {"key": "PortItem", "skip": True},
    "useraccounts": {"key": "UserItem", "skip": True},
    "disks": {"key": "DiskItem", "skip": True},
    "volumes": {"key": "VolumeItem", "skip": True},
    "network-dns": {"key": "DnsEntryItem", "skip": True},
    "network-route": {"key": "RouteEntryItem", "skip": True},
    "network-arp": {"key": "ArpEntryItem", "skip": True},
    "sysinfo": {"key": "SystemInfoItem", "skip": True},
    "services": {"key": "ServiceItem", "skip": True},
    "hivelist": {"key": "HiveItem", "skip": True},
    "drivers-modulelist": {"key": "ModuleItem", "skip": True},
    "drivers-signature": {"key": "DriverItem", "skip": True},
    "formhistory": {"key": "FormHistoryItem", "skip": True},
    "kernel-hookdetection": {"key": "HookItem", "skip": True},
}


def convert_both_pandas(argument, offset=0):
    """
        convert_both_pandas: parse date field and convert to it to proper
        in:
            argument: object to parse
        out:
            parsed data
    """
    try:
        d = ciso8601.parse_datetime(argument)
        d += datetime.timedelta(seconds=offset)
        return pd.Series(
            [d.isoformat(timespec="seconds"), str(int(d.timestamp() * 1000000))]
        )
    except (ValueError, OSError):
        logging.warning(f"[MAIN - WARNING] date {str(argument)} not valid")
        return pd.Series([None, None])


def convert_both(argument, offset=0):
    """
        convert_both: parse date field and convert to it to proper
        in:
            argument: object to parse
        out:
            parsed data
    """
    try:
        d = ciso8601.parse_datetime(argument)
        d += datetime.timedelta(seconds=offset)
        return d.isoformat(timespec="seconds"), str(int(d.timestamp() * 1000000))
    except (ValueError, OSError):
        logging.warning(f"[MAIN - WARNING] date {str(argument)} not valid")
        return None, None


def convert_skew(offset):
    """
        convert_skew: return offset for xml file in seconds
        in:
            offset: skew offset in custom format
        out:
            offset in secs or 0 if error
    """
    try:
        return int(offset.replace("PT", "").replace("S", ""))
    except:
        logging.warning(f"[MAIN - WARNING] problem parsing skew: {offset}")
        return 0


class MansToEs:
    def __init__(self, args):
        self.filename = args.filename
        self.index = args.index
        self.name = args.name
        self.bulk_size = args.bulk_size
        self.cpu_count = args.cpu_count
        self.folder_path = self.filename + "__tmp"
        self.offset_stateagentinspector = None
        self.es_info = {"host": args.es_host, "port": args.es_port}
        self.upload_parts = []
        self.filelist = {}
        self.ioc_alerts = []
        self.exd_alerts = []
        self.generic_items = {}

        es = Elasticsearch([self.es_info])
        if not es.ping():
            raise ValueError("Connection failed")

        logging.debug(f"[MAIN] Start parsing {args.filename}.")
        logging.debug(f"[MAIN] Pushing on {args.name} index and {args.index} timeline")

    def handle_stateagentinspector(self, path, item_detail):
        """
            handle_item: streaming function for xmltodict (stateagentitem)
            In:
                path: xml item path
        """
        item = {}
        uid = path[1][1]["uid"]
        item["uid"] = uid
        item["SubEventType"] = item_detail["eventType"]
        # stateagentinspector has only timestamp field and is parsed now!
        datetime, timestamp = convert_both(
            item_detail["timestamp"], self.offset_stateagentinspector
        )
        item["timestamp"] = timestamp
        item["datetime"] = datetime
        item["datetype"] = "timestamp"
        item["message"] = item_detail["eventType"]
        if type(item_detail["details"]["detail"]) in (collections.OrderedDict, dict):
            x = item_detail["details"]["detail"]
        else:
            for x in item_detail["details"]["detail"]:
                item[x["name"]] = x["value"]
        if uid in self.ioc_alerts:
            item["source"] = "IOC"
            item["resolution"] = "ALERT"
            item["ALERT"] = True
            item["alert_code"] = (
                MANS_FIELDS["stateagentinspector"]["SubEventType"]
                .get(item_detail["eventType"], {})
                .get("hits_key", None),
            )
        self.generic_items.setdefault(path[1][0], []).append(item)
        return True

    def handle_item(self, path, item_detail):
        """
            handle_item: streaming function for xmltodict
            In:
                path: xml item path
                item_detail: xml item data
        """
        item_detail["message"] = path[1][0]
        self.generic_items.setdefault(path[1][0], []).append(item_detail)
        return True

    def generate_df(self, file, offset, filetype, stateagentinspector=False):
        """
            Generate dataframe from xml file
        """
        xmltodict.parse(
            file.read(),
            item_depth=2,
            item_callback=self.handle_stateagentinspector
            if stateagentinspector
            else self.handle_item,
        )
        key_type = MANS_FIELDS[filetype]["key"]
        if self.generic_items.get(key_type, []) == []:
            return None, False
        df = pd.DataFrame(self.generic_items[key_type])
        df["mainEventType"] = filetype
        return df, True

    def extract_mans(self):
        """
            Unzip .mans file
        """
        zip_ref = zipfile.ZipFile(self.filename, "r")
        zip_ref.extractall(self.folder_path)
        zip_ref.close()
        logging.debug(f"[MAIN] Unzip file in {self.folder_path} [✔]")

    def delete_temp_folder(self):
        try:
            shutil.rmtree(self.folder_path)
            logging.debug("[MAIN] temporary folder deleted [✔]")
        except:
            logging.warning("[MAIN - WARNING] failed to delete temporary folder")

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
                        if item["generator"] == "stateagentinspector":
                            self.offset_stateagentinspector = convert_skew(
                                res["timestamps"][0]["skew"]
                            )
                        self.filelist[item["generator"]].append(
                            (res["payload"], convert_skew(res["timestamps"][0]["skew"]))
                        )
        logging.debug("[MAIN] Parsing Manifest.json [✔]")

    def parse_hits(self):
        """
            Get hit and alert from hits.json file
        """
        if not os.path.exists(os.path.join(self.folder_path, "hits.json")):
            logging.debug("[MAIN] Parsing Hits.json [missing]")
        else:
            with open(os.path.join(self.folder_path, "hits.json"), "r") as f:
                for x in json.load(f):
                    if x.get("data", {}).get("key", None):
                        event_id = str(x["data"]["key"]["event_id"])
                        if event_id not in self.ioc_alerts:
                            self.ioc_alerts.append(event_id)
                    elif x.get("data", {}).get("documents", None) or x.get(
                        "data", {}
                    ).get("analysis_details", None):
                        (alert_datetime, alert_timestamp) = convert_both(
                            x["data"]["earliest_detection_time"], 0  # ??
                        )
                        self.exd_alerts.append(
                            {
                                "source": x["source"],
                                "resolution": x["resolution"],
                                "process id": x["data"]["process_id"],
                                "process name": x["data"]["process_name"],
                                "alert_code": "XPL",
                                "datetime": alert_datetime,
                                "timestamp": alert_timestamp,
                                "ALERT": True,
                                "message": "PID: %s PROCESS: %s"
                                % (
                                    str(x["data"]["process_id"]),
                                    x["data"]["process_name"],
                                ),
                            }
                        )
            if len(self.exd_alerts) > 0:
                es = Elasticsearch([self.es_info])
                helpers.bulk(
                    es, self.exd_alerts, index=self.index, doc_type="generic_event"
                )
            logging.debug(
                "[MAIN] Parsing Hits.json - %d alerts found [✔]"
                % (len(self.exd_alerts) + len(self.ioc_alerts))
            )

    def process(self):
        """
            Process all files contained in .mans extracted folder
        """
        files_list = []
        for filetype in self.filelist.keys():
            # If filetype is new for now it's skipped
            if filetype not in MANS_FIELDS.keys():
                logging.warning(
                    f"[MAIN] {filetype} filetype not recognize. Send us a note! - SKIP"
                )
                continue
            # Ignore items if not related to timeline
            # TODO: will use them in neo4j for relationship
            if MANS_FIELDS[filetype].get("skip", False):
                logging.debug(f"[MAIN] SKIP {filetype}")
                continue
            # Read all files related to the type
            for (file, offset) in self.filelist[filetype]:
                files_list.append((filetype, file, offset))

        with Pool(processes=self.cpu_count) as pool:
            res = pool.starmap_async(self.process_file, files_list).get()
        logging.debug("[MAIN] Pre-Processing [✔]")

    def process_file(self, filetype, file, offset):
        """
            process_file: parse xml to df and clean it
            In:
                filetype: filetype of the xml
                file: xml file pointer 
                offset: offset to add to date fields
        """
        info = MANS_FIELDS[filetype]

        logging.debug(f"[{filetype:<20} {file}] df [ ] - date [ ] - message [ ]")
        df, valid = self.generate_df(
            open(os.path.join(self.folder_path, file), "r", encoding="utf8"),
            offset,
            filetype,
            filetype == "stateagentinspector",
        )

        if not valid:
            logging.error(f"[{filetype:<20} {file}] -- XML not valid or empty")
            return

        # check all date field, if not present remove them, if all not valid skip
        datefields = [x for x in info["datefields"] if x in df.columns]
        if len(datefields) == 0:
            logging.debug(f"[{filetype:<20} {file}] No valid time field - SKIP")
            return

        if filetype == "stateagentinspector":
            # each subtype has different fields and message fields
            subevents = df["SubEventType"].unique()
            # logging.debug(f"[{filetype:<20} {file}] contains followings subtypes: {subevents}")
            for sb in subevents:

                # if it's new we cannot continue
                if sb not in info["SubEventType"].keys():
                    logging.debug(
                        f"[{filetype:<20} {sb:<24} {file}] -- new subtype found. Send us a note!"
                    )
                    continue

                # take only valid column for that subtype
                subdf = df[df["SubEventType"] == sb]

                # add messages based on selected fields value
                if info["SubEventType"][sb].get("message_fields", None):
                    subdf.loc[:, "message"] = subdf.apply(
                        lambda row: " - ".join(
                            [row["message"]]
                            + [
                                str(row[mf])
                                for mf in info["SubEventType"][sb]["message_fields"]
                                if row.get(mf, None)
                            ]
                        )
                        + " [%s]" % row["datetype"],
                        axis=1,
                    )
                else:
                    subdf.loc[:, "message"] = subdf.apply(
                        lambda row: row["message"] + " [%s]" % row["datetype"], axis=1
                    )
                subdf.loc[:, "timestamp_desc"] = subdf.loc[:, "message"]
                logging.debug(
                    f"[{filetype:<20} {sb:<24} {file}] df [✔] - date [✔] - message [✔]"
                )
                subdf.dropna(axis=1, how="all").to_json(
                    os.path.join(self.folder_path, f"tmp___{sb}_{file}.json"),
                    orient="records",
                    lines=True,
                )
        else:
            logging.debug(f"[{filetype:<20} {file}] df [✔] - date [ ] - message [ ]")
            # melt multiple date fields
            if len(datefields) > 1:
                df = df.melt(
                    id_vars=[x for x in df.columns if x not in datefields],
                    var_name="datetype",
                    value_name="datetime",
                )
            else:
                df["datetype"] = datefields[0]
                df = df.rename(columns={datefields[0]: "datetime"})
            df = df[df["datetime"].notnull()]

            # convert datetime to default format
            df[["datetime", "timestamp"]] = df["datetime"].apply(
                lambda x: convert_both_pandas(x, offset)
            )

            logging.debug(f"[{filetype:<20} {file}] df [✔] - date [✔] - message [ ]")

            # Add messages based on selected fields value
            if info.get("message_fields", None):
                df.loc[:, "message"] = df.apply(
                    lambda row: " - ".join(
                        [row["message"]]
                        + [
                            str(row[mf])
                            for mf in info["message_fields"][row["datetype"]]
                            if row.get(mf, None)
                        ]
                    )
                    + " [%s]" % row["datetype"],
                    axis=1,
                )
            else:
                df.loc[:, "message"] = df.apply(
                    lambda row: row["message"] + " [%s]" % row["datetype"], axis=1
                )
            df.loc[:, "timestamp_desc"] = df.loc[:, "message"]
            logging.debug(f"[{filetype:<20} {file}] df [✔] - date [✔] - message [✔]")
            df.dropna(axis=1, how="all").to_json(
                os.path.join(self.folder_path, f"tmp___{file}.json"),
                orient="records",
                lines=True,
            )
        del df

    def to_elastic(self):
        """
            to_elastic: push dataframe to elastic index
        """
        elk_items = []
        for file in glob(self.folder_path + "/tmp__*.json"):
            elk_items += open(file, "r").readlines()
        logging.debug(f"[MAIN] Pushing {len(elk_items)} items to elastic")
        es = Elasticsearch([self.es_info])
        collections.deque(
            helpers.parallel_bulk(
                es,
                elk_items,
                index=self.index,
                doc_type="generic_event",
                chunk_size=self.bulk_size,
                request_timeout=60,
            ),
            maxlen=0,
        )
        logging.debug("[MAIN] Parallel elastic push [✔]")


def main():
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
        "--version", dest="version", action="version", version="%(prog)s 1.4"
    )
    args = parser.parse_args()

    if not all([args.name, args.index, args.es_port, args.es_host]):
        parser.print_usage()
    else:
        try:
            mte = MansToEs(args)
            mte.extract_mans()
            mte.parse_manifest()
            mte.parse_hits()
            mte.process()
            mte.to_elastic()
            mte.delete_temp_folder()
            logging.debug("[MAIN] Operation Completed [✔✔✔]")
        except:
            logging.exception("Error parsing .mans")
            return False
    return True


if __name__ == "__main__":
    if not main():
        sys.exit(1)
    else:
        sys.exit(0)
