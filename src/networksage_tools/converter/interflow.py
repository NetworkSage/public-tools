"""
    Copyright (c) 2021 David Pearson (david@seclarity.io)
    Date: 06/03/2021
    This file contains the Interflow class, which captures the fields that are found in Stellar Cyber's Interflow format
    for network traffic. Note that there are MANY fields in Interflow that will not be a part of this converter, as they
    are not necessary to convert to Secflow. The file is expected to contain one Interflow per line in JSON format, and
    any DNS Interflow records (if provided) are expected to also be contained within the file. For non-DNS records,
    below is an example Interflow record that includes only the fields we need.

    {"timestamp": 1656517273641, "duration": 401, "_id": "6c0liABC8qtQm3loQr7H", "msg_class": "interflow_traffic", "srcip": "172.18.40.120", "srcport": 55503,"dstip": "142.251.40.65", "dstip_host": "ci3.googleusercontent.com", "dstport": 80, "proto_name": "tcp", "outbytes_total": 0, "inpkts_delta": 5, "outpkts_delta": 0, "inbytes_total": 17765}

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.
"""

class Interflow():
    def __init__(self, flowdata, is_json=False):
        likely_ms = True  # the time information is likely in milliseconds, so fix up duration and timestamp
        if is_json:
            try:
                self.secflow_key = f'{flowdata["srcip"]}:{flowdata["srcport"]}'
                if len(str(flowdata["timestamp"])) == 13:
                    if "." not in str(flowdata["timestamp"]):
                        self.timestamp = float(flowdata["timestamp"]) / 1000.0
                    else:
                        print("Unrecognized timestamp format. Results may be wrong.")
                        likely_ms = False
                        self.timestamp = float(flowdata["timestamp"])
                elif len(str(flowdata["timestamp"])) == 10:
                    likely_ms = False
                    self.timestamp = float(flowdata["timestamp"])
                self.unique_id = f'{flowdata["_id"]}'
                self.source_ip = f'{flowdata["srcip"]}'
                self.source_port = f'{flowdata["srcport"]}'
                self.dest_ip = f'{flowdata["dstip"]}'
                self.dest_port = f'{flowdata["dstport"]}'
                self.proposed_destname = f'{flowdata["dstip_host"]}' if "dstip_host" in flowdata else None
                self.trans_proto = f'{flowdata["proto_name"]}' if "proto_name" in flowdata else "-"
                self.protocol_information = ""
                if self.trans_proto == "icmp":
                    self.source_port = ""
                    self.dest_port = ""
                    self.protocol_information = "ICMP"
                    self.secflow_key = f'{self.source_ip}:{self.protocol_information}-{self.dest_ip}:{self.protocol_information}'
                self.service = f'{flowdata["service"]}' if "service" in flowdata else "-"
                if "duration" in flowdata:
                    if likely_ms:
                        self.duration = f'{float(flowdata["duration"]) / 1000.0}'
                    else:
                        self.duration = f'{flowdata["duration"]}'
                else:
                    self.duration = "-"
                self.source_bytes = f'{flowdata["outbytes_total"]}' if "outbytes_total" in flowdata else "-"
                self.dest_bytes = f'{flowdata["inbytes_total"]}' if "inbytes_total" in flowdata else "-"
                self.source_pkts = f'{flowdata["outpkts_delta"]}' if "outpkts_delta" in flowdata else "0"
                self.dest_pkts = f'{flowdata["inpkts_delta"]}' if "inpkts_delta" in flowdata else "0"
            except Exception as e:
                print("Something went wrong while trying to parse JSON record for Interflow:\n{}".format(e))
                self.secflow_key = None
        else:
            print("Interflow data not recognized. We only accept Interflow records in JSON format, with each record on its own line.")
            self.secflow_key = None