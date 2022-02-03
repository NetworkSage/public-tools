"""
    Copyright (c) 2021 David Pearson (david@seclarity.io)
    Date: 06/02/2021
    This file contains utilities that allow a Zeek conn (and an optional dns) log to be converted into equivalent
    secFlows.

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.
"""

import re
import sys
import magic
from networksage_tools.common_utilities import iputils
from networksage_tools.common_utilities import secflow
from networksage_tools.converter import zeekflow


def remove_local_traffic_from_zeek_file(utils):
    """Removes the local traffic from the incoming Zeek file dictionary.
    """
    tmp_dict = dict()
    for flow_group in utils.zeekflows.keys():
        tmp_flowlist = []  # clear it each time through the group
        for flow in utils.zeekflows[flow_group]:
            if iputils.check_if_local_ip(flow.source_ip) and iputils.check_if_local_ip(flow.dest_ip):
                # print("removing", flow.source_ip, "<->", flow.dest_ip, "from flows dictionary.")
                continue
            else:  # one of the sides is not local
                tmp_flowlist += [flow]
        tmp_dict[flow_group] = tmp_flowlist  # keep only the ones that aren't local-to-local
    utils.zeekflows = tmp_dict


def store_zeekflows(utils):
    """Takes a Zeek file, removes the header lines, and stores the input as a dictionary. We store each line in the file
       as a flow, but then we store each flow object by the key used for secFlows.
    """

    with open(utils.original_filepath) as infile:
        for line in infile:
            if line.startswith("#"):  # it's a comment line
                continue
            flowdata = line.strip().split("\t")
            zeekflow_object = zeekflow.ZeekFlow(flowdata)  # an individual line, which actually doesn't always capture all of the data for a 4-tuple.
            if zeekflow_object.secflow_key not in utils.zeekflows.keys():
                utils.zeekflows[zeekflow_object.secflow_key] = []
            utils.zeekflows[zeekflow_object.secflow_key] += [(zeekflow_object)]


def identify_zeekfile_start_time(utils):
    """Takes a Zeek flows dictionary and finds the earliest time.
    """
    ts = float(99999999999)
    for flow_group in utils.zeekflows.keys():
        for flow in utils.zeekflows[flow_group]:
            ts = min(ts, float(flow.timestamp))
    utils.file_start_time = ts

    # print("File start time:", self.file_start_time)


def convert_zeek_to_secflow(utils):
    """This function takes the original Zeek conn log flows and converts them into secFlows. secFlows may be made up of
       one or more Zeek conn log flows, since Zeek parses out service-related communication between two IP:Port pairs
       separately from the underlying transport-layer (i.e. TCP/UDP) flow. In the logic below, those multiple conn log
       flows are grouped together into a flow group. Generally speaking, this should guarantee that the destination IP
       and port are the same for all of the flows in this group, since source ports should be incrementally increasing
       on the host. It is certainly possible that an adversary could cause the system to use the same source port for
       more than one session, which would cause issues here and in our PCAP analysis. Handling those cases (perhaps by
       using a key requiring the unique 4-tuple of sourceIP:source_port+dest_ip:dest_port) is future work.
    """

    for flow_group in utils.zeekflows.keys():
        # initialize a few variables to keep track of state inside flow groups
        max_nonservice_sb = 0
        max_service_sb = 0
        max_nonservice_db = 0
        max_service_db = 0

        # sort the flows in a flow group by their start timestamp
        utils.zeekflows[flow_group] = sorted(utils.zeekflows[flow_group], key=lambda x: x.timestamp)

        secflow_object = None  # start off empty

        for zeekflow in utils.zeekflows[flow_group]:
            if iputils.check_if_local_ip(str(zeekflow.source_ip)) and iputils.check_if_local_ip(str(zeekflow.dest_ip)):
                break  # we don't want local-to-local traffic!
            if iputils.check_if_local_ip(str(zeekflow.dest_ip)) and not iputils.check_if_local_ip(str(zeekflow.source_ip)):
                print("We think Zeek is wrong in identifying who the source is. Flipping order.")
                zeekflow.flip_zeek_order() # flip things related to bytes and directionality
                secflow_object = secflow.Secflow(zeekflow.secflow_key
                                                , zeekflow.source_port
                                                , zeekflow.dest_ip
                                                , zeekflow.dest_port
                                                , float(zeekflow.timestamp)
                                                , float(utils.file_start_time)
                                                , zeekflow.protocol_information
                                                )  # create a new secFlow object
                utils.secflows[zeekflow.secflow_key] = secflow_object  # store it
            if zeekflow.secflow_key not in utils.secflows.keys():  # we've not collected this sourceIP:source_port
                secflow_object = secflow.Secflow(zeekflow.secflow_key
                                                , zeekflow.source_port
                                                , zeekflow.dest_ip
                                                , zeekflow.dest_port
                                                , float(zeekflow.timestamp)
                                                , float(utils.file_start_time)
                                                , zeekflow.protocol_information
                                                )  # create a new secFlow object
                utils.secflows[zeekflow.secflow_key] = secflow_object  # store it

            # collect packet info from Zeek flow
            secflow_object.source_pkts += int(zeekflow.source_pkts)
            secflow_object.dest_pkts += int(zeekflow.dest_pkts)

            # get the max duration of the flow
            if zeekflow.duration != "-":
                secflow_object.max_ts = max(secflow_object.max_ts, zeekflow.timestamp + float(zeekflow.duration))
            else:
                secflow_object.max_ts = max(secflow_object.max_ts, zeekflow.timestamp)
            # get correct byte counts (according to our secFlow calcuations)
            if zeekflow.service == "-":  # no service identified for this particular flow
                if zeekflow.history == "S":  # and we have ONLY a SYN flag
                    max_nonservice_sb = 0
                    max_nonservice_db = 0
                elif max_nonservice_sb == 0 or max_nonservice_db == 0:
                    if not re.search(r"d", zeekflow.history):  # Zeek saw no payload bytes from the source
                        if not re.search(r"t", zeekflow.history):  # Zeek saw no retransmitted payloads from the source
                            max_nonservice_sb = 0
                        else:
                            if zeekflow.source_bytes == "-": # it's not a protocol that contains bytes in upper layers
                                max_nonservice_sb = 0
                            else:
                                max_nonservice_sb = int(zeekflow.source_bytes)
                    else:
                        if zeekflow.source_bytes == "-": # it's not a protocol that contains bytes in upper layers
                            max_nonservice_sb = 0
                        else:
                            max_nonservice_sb = int(zeekflow.source_bytes)
                    if not re.search(r"D", zeekflow.history):  # Zeek saw no payload bytes from the destination
                        if not re.search(r"t",
                                         zeekflow.history):  # Zeek saw no retransmitted payloads from the destination
                            max_nonservice_db = 0
                        else:
                            max_nonservice_db = int(zeekflow.dest_bytes)
                    else:
                        max_nonservice_db = int(zeekflow.dest_bytes)
                else:
                    max_nonservice_sb = max(max_nonservice_sb, int(zeekflow.source_ip_bytes))
                    max_nonservice_db = max(max_nonservice_db, int(zeekflow.dest_ip_bytes))
            else:
                if max_service_sb == 0 or max_service_db == 0:
                    max_service_sb = int(zeekflow.source_bytes)
                    max_service_db = int(zeekflow.dest_bytes)
                else:
                    max_service_sb = max(max_service_sb, int(zeekflow.source_bytes))
                    max_service_db = max(max_service_db, int(zeekflow.dest_bytes))
        if secflow_object is not None:
            # at end of the flow group, collect what we've captured and update the secFlow object if the value is higher than what we already have
            secflow_object.source_payload_bytes = max(secflow_object.source_payload_bytes
                                                    , max(max_nonservice_sb, max_service_sb))
            secflow_object.dest_payload_bytes = max(secflow_object.dest_payload_bytes
                                                    , max(max_nonservice_db, max_service_db))
            secflow_object.set_secflow_duration()


def validate_file_format(utils):
    """Validate if file is an ASCII text file -- very weak check for Zeek, unfortunately.
    """
    if not re.match(r"^ASCII text$", magic.from_file(utils.original_filepath)):
        print("Error:", utils.original_filepath + ",", "of type", magic.from_file(utils.original_filepath),
              "is not an accepted file type.")
        sys.exit(1)


def zeek_2_secflows(utils):
    """Given a conn log that has been lightly validated, store the Zeek flows, remove any local traffic and convert the
       Zeek flows to secFlows.
    """

    # store file as a dict for easier processing
    store_zeekflows(utils)
    if len(utils.zeekflows) == 0:
        print("No Zeek flows were found in file. No traffic was converted to Secflows.")
        return False

    # remove local connections
    remove_local_traffic_from_zeek_file(utils)

    # get file start time
    identify_zeekfile_start_time(utils)

    # convert from Zeek to secFlow
    convert_zeek_to_secflow(utils)
    return True
