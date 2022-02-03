"""
    Copyright (c) 2021 David Pearson (david@seclarity.io)
    Date: 06/03/2021
    This file contains utility functions and variables that are used by a number of callers.

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.
"""

import collections
import json
import os
import sys
import uuid
from pathlib import Path

class Utilities():
    local_ips_forward_regex = r"^(10|127|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\."
    local_ips_reverse_regex = r"([0-9]{1,3})\.([0-9]{1,3})\.((1[6-9]\.172)|(2[0-9]\.172)|(3[0-1]\.172)|([0-9]{1,3}\.10)|(168\.192))\.in\-addr\.arpa\.$"
    ipv6_regex = r"(([1-9a-fA-F]{1,}:)"  # very basic, meant to filter out virtually anything right now. Also not currently used

    def __init__(self, orig_fp, platform_type, output_dir=None):
        self.active_external_ips = set()
        self.questions = dict()
        self.original_filepath = orig_fp
        if orig_fp is None:
            self.is_streaming = True
        else:
            self.is_streaming = False
        self.output_dir = output_dir # optional place to store the finished file
        self.system_type = platform_type
        self.filtered_filepath = ""
        self.secflows = collections.OrderedDict()  # dict of Secflow objects (TCP, UDP, or ICMP)
        self.file_start_time = float(99999999999)  # set it impossibly high at beginning
        self.tmp_filepath = ""  # file to temporarily store just the secflows with proper formatting. Needed in order to have a consistent file to hash
        self.secflow_output_filepath = ""  # file to store the final output intended to be sent back to the caller
        self.sample_name = ""
        self.secflows_hash = ""  # used to store the hash of the secflows file
        self.zeekflows = collections.OrderedDict()
        self.packet_buffer = collections.deque() #create an empty buffer to store packets that have not yet been processed
        self.stop_thread = False #keep state of whether thread should be stopped

    def cleanup_files(self):
        """Removes any files that were created in the interim but not needed for the final output.
        """
        if not self.zeekflows:  # we were working with PCAP data
            # delete the filtered file, if it exists
            try:
                os.remove(self.filtered_filepath)
            except OSError:
                pass
        # delete the temporary file, if it exists
        try:
            os.remove(self.tmp_filepath)
        except OSError:
            pass
        if self.is_streaming or len(self.secflows) == 0: # only delete if streaming or empty
            # delete the final output .sf file, if it exists
            try:
                os.remove(self.secflow_output_filepath)
            except OSError:
                pass

    def get_timestamp_from_packet_header(self, packet_header):
        """Simple utility to transform packet_header's startTime into a usable float value.
        """
        return float(str(packet_header.getts()[0]) + "." + str(packet_header.getts()[1]).zfill(6))

    def set_secflow_durations(self):
        """Iterates through all secflows and updates their flow duration fields.
        """
        for secflow in self.secflows:
            self.secflows[secflow].set_secflow_duration()

    def save_secflows_to_file(self):
        """Saves secflows to a .sf file for hashing.
        """
        # get the proper file name
        last_dot = self.filtered_filepath.rfind(".")
        if last_dot == -1:  # no extension in file name
            self.tmp_filepath = self.filtered_filepath + ".tmp"
        else:
            self.tmp_filepath = self.filtered_filepath[:last_dot] + ".tmp"

        with open(self.tmp_filepath, "w") as sf_out:
            for secflow in self.secflows.keys():
                if self.secflows[secflow].protocol_information in ["ICMP"]:
                    first_delimiter = self.secflows[secflow].key.find(":")
                    sf_out.write(self.secflows[secflow].key[:first_delimiter] + " <-> " +
                                self.secflows[secflow].dest_name + "\t"
                                + str(self.secflows[secflow].source_pkts) + "\t"
                                + str(self.secflows[secflow].source_payload_bytes) + "\t"
                                + str(self.secflows[secflow].dest_pkts) + "\t"
                                + str(self.secflows[secflow].dest_payload_bytes) + "\t"
                                + str(self.secflows[secflow].relative_start_time) + "\t"
                                + str(self.secflows[secflow].protocol_information) + "\t"
                                + str(self.secflows[secflow].duration) + "\n")
                else:
                    sf_out.write(self.secflows[secflow].key + " <-> " +
                                self.secflows[secflow].dest_name + ":" + self.secflows[secflow].dest_port + "\t"
                                + str(self.secflows[secflow].source_pkts) + "\t"
                                + str(self.secflows[secflow].source_payload_bytes) + "\t"
                                + str(self.secflows[secflow].dest_pkts) + "\t"
                                + str(self.secflows[secflow].dest_payload_bytes) + "\t"
                                + str(self.secflows[secflow].relative_start_time) + "\t"
                                + str(self.secflows[secflow].protocol_information) + "\t"
                                + str(self.secflows[secflow].duration) + "\n")

    def get_random_uuid(self) -> object:
        """Assigns a random uuid to the sample file
        """
        return str(uuid.uuid4()).replace("-", "")

    def set_hash_value_for_sample(self, uuid) -> object:
        """Assigns a uuid to the sample file
        """
        self.secflows_hash = uuid

    def prepare_final_output_file(self):
        """Captures Secflows and other important metadata in JSON format for final transmission back to the caller
            (usually an API).
        """
        if self.is_streaming: # this is streaming mode
            time_str = str(self.file_start_time)
            start_time_str = str(time_str[:time_str.find(".")])
            self.secflow_output_filepath = self.system_type + "_" + start_time_str + ".sf"
        else:
            if not self.is_streaming and not Path(self.tmp_filepath).is_file():
                print("Warning:", self.tmp_filepath, "does not exist. Aborting.")
                sys.exit(1)
            else:
                # get the proper file name
                last_dot = self.filtered_filepath.rfind(".")
                if last_dot == -1:  # no extension in file name
                    self.secflow_output_filepath = self.filtered_filepath + ".sf"
                else:
                    self.secflow_output_filepath = self.filtered_filepath[:last_dot] + ".sf"

        """Use the dictionary version of this file to convert it (plus some other information) to JSON
        """
        # first, make sure we're in ascending relativeStart order
        self.secflows = {k: v for k, v in sorted(self.secflows.items(), key=lambda item: item[1].relative_start_time)}

        with open(self.secflow_output_filepath, "w") as secflow_outfile:
            self.sample_name = os.path.basename(self.secflow_output_filepath)
            rows = []
            for flow in self.secflows.keys():
                if self.secflows[flow].protocol_information in ["ICMP"]:
                    first_delimiter = self.secflows[flow].key.find(":")
                    rows += [{"src": self.secflows[flow].key[:first_delimiter],
                              "dst": self.secflows[flow].dest_name,
                              "destinationNameSource": self.secflows[flow].destination_name_source,
                              "srcPkts": self.secflows[flow].source_pkts,
                              "srcBytes": self.secflows[flow].source_payload_bytes,
                              "dstPkts": self.secflows[flow].dest_pkts, "dstBytes": self.secflows[flow].dest_payload_bytes,
                              "relativeStart": self.secflows[flow].relative_start_time,
                              "protocolInformation": self.secflows[flow].protocol_information,
                              "duration": self.secflows[flow].duration}]
                else:
                    rows += [{"src": self.secflows[flow].key,
                              "dst": self.secflows[flow].dest_name + ":" + self.secflows[flow].dest_port,
                              "destinationNameSource": self.secflows[flow].destination_name_source,
                              "srcPkts": self.secflows[flow].source_pkts,
                              "srcBytes": self.secflows[flow].source_payload_bytes,
                              "dstPkts": self.secflows[flow].dest_pkts, "dstBytes": self.secflows[flow].dest_payload_bytes,
                              "relativeStart": self.secflows[flow].relative_start_time,
                              "protocolInformation": self.secflows[flow].protocol_information,
                              "duration": self.secflows[flow].duration}]
            # metadata for the file that is important to keep track of
            secflow_output = {"hash": self.secflows_hash, "trafficDate": str(self.file_start_time),
                          "fileName": self.sample_name,
                          "flashes": rows}  # note: can rename flashes to secflows
            json.dump(secflow_output, secflow_outfile)
            return self.secflow_output_filepath

    def check_output_sanity(self):
        """Determines if there are any issues with the final output file. Issues could include:
                1. having no resulting FLASHES (this is atypical but not an error in this case)
                2. having a default time (meaning that we didn't process anything)
        """

        try:
            with open(self.secflow_output_filepath, "r") as secflow_outfile:
                out_file = json.load(secflow_outfile)
                if out_file["trafficDate"] == "99999999999.0": #default date value
                    if len(out_file["flashes"]) == 0:
                        print("File has no secflows to upload. NetworkSage currently handles only IPv4 to or from the Internet. Nothing to do.")
                        return
                    else:
                        print("Error: File seems to have secflows to upload, but date of traffic wasn't correctly learned. Aborting.")
                        sys.exit(1)
        except:
            print("Something went wrong while trying to check output file for sanity. Aborting.")
            self.cleanup_files()
            sys.exit(1)