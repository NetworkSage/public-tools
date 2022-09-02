"""
    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io).
    This file contains utilities that allow a Stellar Cyber Interflow (and an optional dns) log to be converted into
    equivalent secFlows.

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
    See the accompanying LICENSE file for more information.
"""
import json
from networksage_tools.common_utilities import iputils
from networksage_tools.common_utilities import secflow
from networksage_tools.converter import generic_flowutils
from networksage_tools.converter import interflow


def store_interflows(utils):
    """Takes a JSON file of Interflow records (either one JSON record per line or a list of JSON records separated by
       commas) and stores the fields that we need from the input as a dictionary. Each record is stored as a genericflow
       object with each object accessible by the key used for secFlows.
    """
    is_json = True if utils.file_format is not None and utils.file_format == "JSON data" else False
    with open(utils.original_filepath) as infile:
        if is_json:
            flows = []
            for line in infile:
                data = json.loads(line)
                if type(data) == list:
                    # list of flows, so capture them all
                    flows = data
                elif type(data) == dict:
                    flows += [data]
                else:
                    print(f"Unrecognized JSON data {type(data)}")
                    return None
        else:
            print("Expected JSON but did not get it. Quitting.")
            return None
        for flowdata in flows:
            interflow_object = interflow.Interflow(flowdata, is_json)
            if interflow_object.secflow_key is None:
                print("Failed to capture key for Interflow object; skipping record. Please see errors before this!")
                continue
            if interflow_object.secflow_key not in utils.genericflows.keys():
                utils.genericflows[interflow_object.secflow_key] = []
            utils.genericflows[interflow_object.secflow_key] += [(interflow_object)]


def convert_interflow_to_secflow(utils):
    """This function takes the original Interflow objects (stored as genericflows) and converts them into secFlows.
       secFlows are made up of one Interflow record, since Stellar Cyber aggregates all information between two IP:Port
       pairs into one record.
    """

    for flow_group in utils.genericflows.keys():
        # sort the flows in a flow group by their start timestamp
        utils.genericflows[flow_group] = sorted(utils.genericflows[flow_group], key=lambda x: x.timestamp)

        secflow_object = None  # start off empty

        for interflow in utils.genericflows[flow_group]:
            if iputils.check_if_local_ip(str(interflow.source_ip)) and iputils.check_if_local_ip(str(interflow.dest_ip)):
                break  # we don't want local-to-local traffic!
            if interflow.secflow_key not in utils.secflows.keys():  # we've not collected this sourceIP:source_port
                secflow_object = secflow.Secflow(interflow.secflow_key
                                                , interflow.source_port
                                                , interflow.dest_ip
                                                , interflow.dest_port
                                                , float(interflow.timestamp)
                                                , float(utils.file_start_time)
                                                , interflow.protocol_information
                                                )  # create a new secFlow object
                utils.secflows[interflow.secflow_key] = secflow_object  # store it

            # collect packet info from Interflow
            secflow_object.source_pkts += int(interflow.source_pkts)
            secflow_object.dest_pkts += int(interflow.dest_pkts)

            # collect byte info from Interflow, if it exists
            try:
                secflow_object.source_payload_bytes += int(interflow.source_bytes)
            except:
                pass  # it's legitimately possible that source bytes is "-"
            try:
                secflow_object.dest_payload_bytes += int(interflow.dest_bytes)
            except:
                pass  # it's legitimately possible that dest bytes is "-"

            # get the max duration of the flow
            if interflow.duration != "-":
                secflow_object.max_ts = max(secflow_object.max_ts, interflow.timestamp + float(interflow.duration))
            else:
                secflow_object.max_ts = max(secflow_object.max_ts, interflow.timestamp)
            # if the Interflow has a name for the destination, capture it now
            if interflow.proposed_destname is not None:
                secflow_object.dest_name = interflow.proposed_destname
        if secflow_object is not None:
            secflow_object.set_secflow_duration()


def interflow_2_secflows(utils, dns):
    """Given a JSON log file of Interflow records that has been lightly validated, store the Interflows, collect both
       local and public DNS lookups, remove any  local traffic, and convert the remaining Interflows to Secflows.
    """

    # store file as a dict for easier processing
    store_interflows(utils)

    # collect DNS records (both local and public lookups)
    dns.collect_dns_records_from_interflow_sample()

    # remove local connections
    generic_flowutils.remove_local_traffic_from_generic_flows(utils)

    if len(utils.genericflows) == 0:
        print("No Interflows were found in file. No traffic was converted to Secflows.")
        return False

    # get file start time
    generic_flowutils.identify_earliest_flow_start_time(utils)

    # convert from Interflow to secFlow
    convert_interflow_to_secflow(utils)
    return True


def json_extract(obj, key, dict_expected=False):
    """Recursively fetch values from nested JSON. Code credit to Todd Birchard at
    https://hackersandslackers.com/extract-data-from-complex-json-python/. Slightly modified to handle dicts as end
    types.
    """
    arr = []
    def extract(obj, arr, key, dict_expected=False):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    if dict_expected and isinstance(v, dict):
                        arr.append(v)
                    else:
                        extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                if dict_expected and isinstance(item, dict):
                    arr.append(item)
                else:
                    extract(item, arr, key)
        return arr
    values = extract(obj, arr, key, dict_expected)
    return values