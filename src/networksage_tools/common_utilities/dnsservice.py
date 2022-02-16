"""
    Copyright (c) 2021 David Pearson (david@seclarity.io)
    Date: 06/03/2021
    This file contains the DnsService class, which keeps the state of all DNS data for the creation of
    well-named Secflows. This class has helper functions to control passive naming from the incoming
    file we're analyzing and from recently seen sessions.

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.
"""

import re
import socket
import pickle
import ipaddress
from pathlib import Path
from networksage_tools.common_utilities import iputils
from networksage_tools.common_utilities import packet
from networksage_tools.common_utilities import utilities

class DnsService:
    def __init__(self, utils):
        self.questions = dict()
        self.passive_dns_names_dict = dict()
        self.short_term_pdns_dict = dict() # saves passive DNS that was learned recently, but not necessarily during this streaming session
        self.active_dns_names = dict()
        self.unique_passive_dns_names = dict()  # results that only have one name for an IP in this file
        self.short_term_passive_dns_lock_name = "./shortTermPassiveDNS.pkl.lock"
        self.long_term_passive_dns_file_name = ""
        self.short_term_passive_dns_filename = ""
        self.dns_logfile_path = None
        if utils is None:  # shouldn't happen
            self.utils = utilities.Utilities("", "")
        else:
            self.utils = utils

    def order_passive_dns_by_timestamp(self):
        """Makes sure entries are sorted in order of timestamps
        """
        for entry in self.passive_dns_names_dict.keys():
            self.passive_dns_names_dict[entry] = sorted(self.passive_dns_names_dict[entry], key=lambda x: x[0])

    def get_unique_passive_dns_names(self):
        """Entries in this set only have one name (in this file) per IP address. This is used to update our
           long-term passive DNS file.
        """
        for entry in self.passive_dns_names_dict.keys():
            tmp_set = set()
            for tuple in self.passive_dns_names_dict[entry]:
                name = tuple[1]
                tmp_set.add(name)
            if len(tmp_set) == 1:
                self.unique_passive_dns_names[entry] = tmp_set.pop()  # grab the only name

    def parse_dns_records_from_dns_log(self):
        """Takes a Zeek dns.log, then creates and returns a dictionary of lists of tuples of packet source ports (for
           later filtering of local lookups), start times (for use later in figuring out which DNS name to use)
           and A or PTR record DNS resolutions found in the file. The resolutions are stored by name as follows:
              self.questions["someDomain.tld."]=[(someSrcPort, someTimestamp, "7.8.9.10"),(someSrcPort, someTimestamp, "1.2.3.4")]
              self.questions["4.3.2.1.in-addr.arpa."]=[(someSrcPort, someTimestamp, "someOtherDomain.tld.")]
           TODO: Handle PTR records for Zeek!
        """
        with open(self.dns_logfile_path, "r") as dns_logfile:
            for line in dns_logfile:
                if line.startswith("#"):  # ignore comment lines
                    continue
                dns_record = line.strip().split("\t")
                start_time = float(dns_record[0])
                roundtrip_time = dns_record[8]
                source_port = dns_record[3]
                q_name = dns_record[9] + "."  # we expect FQDNs in our files at this point
                q_class = dns_record[10]
                q_type = dns_record[12]
                rcode_name = dns_record[15]
                answers = dns_record[21]
                internet_a_record = False
                other_unknown_collectible_record = False
                if q_class == "1" and q_type == "1": # we only want successful DNS lookups to the Internet for A records.
                    internet_a_record = True
                elif roundtrip_time == "-" and rcode_name == "NOERROR": # these seem to occur when converting from PCAP to Zeek
                    other_unknown_collectible_record = True
                else: # everything else should be thrown away
                    continue

                if q_name not in self.questions.keys():
                    self.questions[q_name] = set()
                if answers.find(",") != -1:  # multiple answers
                    answers_list = answers.split(",")
                    for answer in answers_list:
                        try:
                            self.questions[q_name].add((source_port, start_time, str(ipaddress.ip_address(answer))))
                        except:  # it wasn't an IP address, so we'll skip collecting it
                            #print("Had an error with", answer)
                            continue
                else:
                    self.questions[q_name].add((source_port, start_time, answers))


    def parse_dns_records_from_capture_file(self):
        """Takes a capture file, then creates and returns a dictionary of lists of tuples of packet source ports (for
           use in filtering later), start times (for use later in figuring out which DNS name to use) and A or PTR
           record DNS resolutions found in the file. The resolutions are stored by name as follows:
              self.questions["someDomain.tld."]=[(someSrcPort, someTimestamp, "7.8.9.10"),(someSrcPort, someTimestamp, "1.2.3.4")]
              self.questions["4.3.2.1.in-addr.arpa."]=[(someSrcPort, someTimestamp, "someOtherDomain.tld.")]
           The parsing that occurs in this function is correlated with the DNS header, and (I believe) should
           handle both UDP and TCP DNS queries.
        """
        try:
            import pcapy
        except ImportError:
            print("Couldn't import pcapy")

        with pcapy.open_offline(self.utils.original_filepath) as capfile:
            capfile.setfilter("port domain")
            (hdr, pkt) = capfile.next()
            while hdr is not None:
                # we should only be getting DNS records now, so parse accordingly
                packet_info = packet.PacketInfo(pkt, hdr, self)  # prep everything for later use
                try:
                    is_resp = (pkt[packet_info.upper_layer_start + 2] > 127)  # highest bit would be 1, so must be above 127
                except:  # packet has no upper layer protocol (such as TCP SYN w/ no data)
                    hdr, pkt = capfile.next()
                    continue
                is_normal_query = (pkt[packet_info.upper_layer_start + 2] ^ 128 < 8)
                # bits 1-4 (0-based) of byte correspond to normal query (value should be 0)
                if is_resp and is_normal_query:  # only parse when needed
                    self.parse_local_lookup_from_packet(packet_info, pkt)
                else:  # skip query questions and/or non-normal responses
                    hdr, pkt = capfile.next()
                    continue
                hdr, pkt = capfile.next()


    def parse_local_lookup_from_packet(self, packet_info, pkt):
        txid = str(int.from_bytes(pkt[packet_info.upper_layer_start : packet_info.upper_layer_start + 2], "big"))
        num_qs = int.from_bytes(pkt[packet_info.upper_layer_start + 4 : packet_info.upper_layer_start + 6], "big")
        cnt = 0
        null_position = 0
        has_an_a_record = False
        has_ptr_record = False
        q_name = ""

        # there can be more than 1 question, so handle them all
        while cnt < num_qs:
            null_position = pkt[((packet_info.upper_layer_start + 13)
                                + (4 * cnt)
                                + null_position
                                ):].find(b"\x00")
            if int.from_bytes(pkt[(packet_info.upper_layer_start + 13) + null_position + 1: (packet_info.upper_layer_start + 13)
                                                                                            + null_position + 3]
                                , "big") == 1: # only do this for A records
                has_an_a_record = True
                if cnt == 0:
                    q_name=re.sub(r"[\x00-\x20]"
                                , r"."
                                , pkt[(packet_info.upper_layer_start + 13): ((packet_info.upper_layer_start + 13)
                                                                            + null_position )].decode("ascii")) + "."
                    if q_name not in self.questions.keys():
                        self.questions[q_name] = set() # we don't yet have the answer
                else:
                    print("Multi-question DNS responses not currently implemented")
                    ###TODO. May not be terribly important in common usage, but should be handled at some point.
            elif int.from_bytes(pkt[(packet_info.upper_layer_start + 13)
                                    + null_position + 1 : (packet_info.upper_layer_start + 13) + null_position + 3]
                                , "big") == 12: # only do this for PTR records
                has_ptr_record = True
                if cnt == 0:
                    q_name=re.sub(r"[\x00-\x20]",r".", pkt[(packet_info.upper_layer_start + 13):
                                                            ((packet_info.upper_layer_start + 13)
                                                            + null_position
                                                            )].decode("ascii")) + "."
                    if q_name not in self.questions.keys():
                        self.questions[q_name]= set() # we don't yet have the answer
                else:
                    print("Multi-question DNS responses not currently implemented")
                    ###TODO. May not be terribly important in common usage, but should be handled at some point.
            cnt+=1
        answers_start=((packet_info.upper_layer_start + 13)
                        + (4 * cnt)
                        + null_position
                        +1
                    ) # should be start of Answers section

        # find IP(s) for the A records and capture them
        if has_an_a_record:
            num_bytes_into_answers = 2
            while len(pkt) > (answers_start + num_bytes_into_answers):
                if num_bytes_into_answers == 2: # first time through
                    length_to_skip = 0
                else:
                    if length_to_skip == 0:
                        num_bytes_into_answers += (length_to_skip + 12)
                if pkt[answers_start + num_bytes_into_answers : answers_start + num_bytes_into_answers + 4] == b"\x00\x01\x00\x01": # an A record for an INternet address
                    # ignore TTL
                    try:
                        if int.from_bytes(pkt[answers_start + num_bytes_into_answers + 8 : answers_start + num_bytes_into_answers + 10]
                                        , "big") == 4: # it's an IPv4 A record
                            # add the information about that mapping as a tuple
                            self.questions[q_name].add(
                                                            (packet_info.source_port
                                                            , packet_info.packet_start_time
                                                            , str(ipaddress.ip_address(
                                                                    pkt[answers_start + num_bytes_into_answers + 10 : answers_start + num_bytes_into_answers + 14]
                                                                    )
                                                                )
                                                            )
                                                        )
                    except:
                        print("Some non-fatal error with", str(pkt[answers_start
                                                        + num_bytes_into_answers + 10
                                                        : answers_start
                                                        + num_bytes_into_answers + 14]
                                                    ),
                                                 "in", pkt)
                # calc how far until the next thing we should parse
                length_to_skip = int.from_bytes(pkt[answers_start + num_bytes_into_answers + 8 : answers_start + num_bytes_into_answers + 10]
                                            , "big")
                num_bytes_into_answers += (length_to_skip + 12)
        elif has_ptr_record:
            num_bytes_into_answers = 2
            while len(pkt) > (answers_start + num_bytes_into_answers):
                if num_bytes_into_answers == 2: # first time through
                    length_to_skip = 0
                    name_length = 0
                else:
                    if length_to_skip == 0:
                        num_bytes_into_answers += (length_to_skip + 12)
                if pkt[answers_start + num_bytes_into_answers : answers_start + num_bytes_into_answers + 4] == b"\x00\x0c\x00\x01": #a PTR record for an INternet address
                    #skip TTL
                    name_length = int.from_bytes(pkt[answers_start + num_bytes_into_answers + 8 : answers_start + num_bytes_into_answers + 10]
                                                , "big")
                    try:
                        answer=re.sub(r"[\x00-\x20]"
                            , r"."
                            , pkt[answers_start + num_bytes_into_answers + 10 : answers_start + num_bytes_into_answers + 10 + name_length].decode("ascii")
                                        )[1:]
                    except UnicodeDecodeError as e:
                        #print("had an error decoding",pkt[answers_start+num_bytes_into_answers+10:answers_start+num_bytes_into_answers+10+name_length])
                        pass
                    self.questions[q_name].add((packet_info.source_port, packet_info.packet_start_time, answer))
                length_to_skip = name_length
                num_bytes_into_answers += (length_to_skip + 12)


    def get_passive_dns(self):
        """Takes the file we're analyzing and uses any DNS information contained in it to passively name as many
           of the external IP addresses as possible.
        """
        if not self.utils.zeekflows and self.utils.original_filepath:  # we're dealing with PCAP data
            # collect all of the active external IP addresses that need to be identified (if possible) passively.
            iputils.collect_active_external_ips_from_capture_file(self.utils)

            # collect all of the DNS records we see in our capture file
            self.parse_dns_records_from_capture_file()
        elif self.utils.zeekflows:  # this is Zeek data
            # collect all active external IP addresses that need to be identified
            for secflow in self.utils.secflows.keys():
                if not iputils.check_if_local_ip(str(self.utils.secflows[secflow].dest_ip)):
                    self.utils.active_external_ips.add(self.utils.secflows[secflow].dest_ip)

            # collect all DNS questions from DNS log, if it exists
            if self.dns_logfile_path is not None:
                self.parse_dns_records_from_dns_log()
        elif self.utils.is_streaming: #we're dealing with streaming data
            for secflow in self.utils.secflows.keys():
                if not iputils.check_if_local_ip(str(self.utils.secflows[secflow].dest_ip)):
                    self.utils.active_external_ips.add(self.utils.secflows[secflow].dest_ip)
        """Finally, for those IPs that are active, find the right DNS name and store it in a
           passive_dns_names_dict ordered dictionary keyed by stringified IP address with lists of tuples of resolution
           time and names as the values.
        """
        for name in self.questions.keys():
            for entry in self.questions[name]:
                dns_resolution = entry[2]
                resolution_time = entry[1]
                if dns_resolution in self.utils.active_external_ips:
                    if dns_resolution not in self.passive_dns_names_dict.keys():
                        self.passive_dns_names_dict[dns_resolution] = [(resolution_time, name[:-1])]
                    else:
                        self.passive_dns_names_dict[dns_resolution] += [(resolution_time, name[:-1])]


    def update_passive_dns_repository(self):
        """For all of the passive DNS from the current file, update the global passive DNS file if there
           are no current entries with the same IP address. If there are, delete that line from the passive DNS
           dictionary and do not save a new one.
        """

        long_term_pdns_path = Path(self.long_term_passive_dns_file_name)

        # iterate through current "ip name" for all DNS names learned passively from current file
        if not long_term_pdns_path.is_file():
            print("Warning:", long_term_pdns_path,
                  "does not exist.")
            with open(self.long_term_passive_dns_file_name, "w") as pdns_file:
                print("Created file now.") # just create the file
        with open(self.long_term_passive_dns_file_name, "r") as infile:
            # file is lines of "IP DNSname", so store in a dict with IP as key
            long_term_pdns = dict(line.strip().split(" ") for line in infile)
        self.get_unique_passive_dns_names()

        # search the global passive DNS file for IP-to-name conflicts
        for ip in self.unique_passive_dns_names.keys():
            if ip in long_term_pdns.keys():
                if self.unique_passive_dns_names[ip] == long_term_pdns[ip]:
                    continue  # still the same name, so do nothing
                else: # replace instead of delete, because on average the newer name will be more relevant temporally (since over time, most data will be fresh)
                    #print("Found conflict with name for IP", ip + ". Replacing.")
                    long_term_pdns[ip] = self.unique_passive_dns_names[ip]
            else:  # collect a newly-learned IP-to-name mapping
                long_term_pdns[ip] = self.unique_passive_dns_names[ip]

        # store the updated passive DNS file
        with open(self.long_term_passive_dns_file_name, "w") as outfile:
            for key, value in long_term_pdns.items():
                outfile.write("%s %s\n" % (key, value))

    def map_destination_ips_to_names(self):
        """Rewrite destination IPs (i.e. the thing on the Internet, generally) with names whenever possible.
           The strategy for doing this as correctly as possible is as follows:
                1. Replace any destination IPs that used passive DNS for the EXACT session (by time) from current
                   file.
                2. (streaming-specific) If a short-term passive DNS file exists, see if there is information in there
                   for the EXACT session (by time) we're currently trying to label. If so, label it.
                3. Replace any destination IPs with the most recent name we have from the current file (so if some IP
                   has multiple names for it in this file, we use the one that was most recently resolved at the time
                   we see this session.
                4. (streaming-specific) If a short-term passive DNS file exists, replace any destination IPs with the
                   most recent name we have. (NOTE: entries expire after ~5 minutes)
                5. Replace any destination IPs that are still unnamed using our long-term passive DNS collection,
                   which only stores names for IPs that we've never seen have more than one name.
                6. Replace any remaining destination IPs with what we learn from an active reverse DNS lookup.
                7. All remaining destination IPs stay as IP addresses that we attempt to lookup server-side.
        """

        self.long_term_passive_dns_file_name = "./longTermPassiveDNS.txt"
        try:
            long_term_pdns_file = Path(self.long_term_passive_dns_file_name)
        except:
            print("Warning:", long_term_pdns_file,
                              "does not exist. Will not use long-term passive DNS for this file.")
        long_term_pdns_dict = dict()
        self.short_term_passive_dns_filename = "./shortTermPassiveDNS.pkl"
        try:
            short_term_pdns_file = Path(self.short_term_passive_dns_filename)
            # the above we don't actually use when we're not streaming, but it's easier to instantiate the file and
            # ignore it than to rewrite the logic a little farther down.
            if self.utils.is_streaming: # only do this for streaming logic
                with open(short_term_pdns_file, "rb") as stpdf:
                    self.short_term_pdns_dict = pickle.load(stpdf)
                # merge short_term_pdns_file into the passive dns names dict so it can be sorted below:
                # get an iterator for this dict so we can pull its changes into the current passive dns names dict
                for entry in self.short_term_pdns_dict.keys():
                    if entry in self.passive_dns_names_dict.keys():
                        for val in self.short_term_pdns_dict[entry]:
                            if val not in self.passive_dns_names_dict[entry]:
                                self.passive_dns_names_dict[entry] += [val]
                    else:
                        self.passive_dns_names_dict[entry] = self.short_term_pdns_dict[entry]
        except:
            if self.utils.is_streaming: # only do this for streaming logic
                print("Short-term passive DNS file", short_term_pdns_file
                    , "does not exist (or some other error). Will not use short-term knowledge for this iteration.")

        self.order_passive_dns_by_timestamp()  # make sure we're sorted by timestamp

        if not long_term_pdns_file.is_file():
            print("Warning:", long_term_pdns_file,
                  "does not exist. Will not use long-term passive DNS for this file.")
        else:
            with open(self.long_term_passive_dns_file_name) as infile:
                # file is lines of "IP DNSname", so store in a dict with IP as key
                long_term_pdns_dict = dict(line.strip().split(" ") for line in infile)

        entry = None # entry is only used for streaming logic
        with open(short_term_pdns_file, "wb") as stpdf_handle: # we actually do plan to overwrite it every time so that we can keep updates sanely
            for secflow in self.utils.secflows.keys():
                named = False  # keep track of whether we've named something each time
                flow_ip = self.utils.secflows[secflow].dest_ip  # local var to make things less verbose in this loop
                if flow_ip in self.passive_dns_names_dict.keys():
                    try:
                        for tuple in list(reversed(self.passive_dns_names_dict[flow_ip])):
                            """The list of tuples is already reverse ordered by timestamp so the first time that is less
                            is the most correct one to use here. """
                            resolution_timestamp = tuple[0]  # grab timestamp
                            name = tuple[1]
                            if resolution_timestamp <= self.utils.secflows[secflow].absolute_start_time:
                                self.utils.secflows[secflow].dest_name = name
                                self.utils.secflows[secflow].destination_name_source = "passive"
                                named = True
                                entry = (resolution_timestamp, name)
                                break  # quit as soon as we get one
                            else:
                                continue
                    except:
                        print("Error: IP address", flow_ip, "has run out of passive_dns_names_dict.")
                        continue
                if not named and self.utils.secflows[secflow].dest_ip in long_term_pdns_dict.keys():
                    # replace any possible destinations with passive DNS from overall PDNS file, if it exists.
                    self.utils.secflows[secflow].dest_name = long_term_pdns_dict[flow_ip]
                    self.utils.secflows[secflow].destination_name_source = "cache"
                    named = True
                if not named:
                    if iputils.check_if_local_ip(flow_ip):
                        print("THIS SHOULDN'T HAPPEN! Info:")
                        self.utils.secflows[secflow].dest_name = flow_ip
                        self.utils.secflows[secflow].destination_name_source = "original"
                        print("\tSource:", self.utils.secflows[secflow].key)
                        print("\tDestination:", self.utils.secflows[secflow].dest_ip+":"+self.utils.secflows[secflow].dest_port)
                        continue  # this should not happen...
                    try:  # if there is something in our current file, grab first one.
                        # print("Deciding to label", flow_ip, "with", self.passive_dns_names_dict[flow_ip][0][1])
                        self.utils.secflows[secflow].dest_name = self.passive_dns_names_dict[flow_ip][0][1]
                        self.utils.secflows[secflow].destination_name_source = "passive"
                        entry = (self.passive_dns_names_dict[flow_ip][0][0], self.passive_dns_names_dict[flow_ip][0][1])
                        named = True
                    except:  # if not, just keep the IP
                        self.utils.secflows[secflow].dest_name = flow_ip
                        self.utils.secflows[secflow].destination_name_source = "original"
                if self.utils.is_streaming: # only do this for streaming logic
                    if named and entry is not None: # we had picked up our name from current file's passive DNS
                        # capture the particular entry in the short-term passive DNS file
                        if flow_ip not in self.short_term_pdns_dict.keys():
                            """If a name doesn't exist in the current version of the short-term dns names dict, we should
                               save it so we can write it to the file.
                            """
                            self.short_term_pdns_dict[flow_ip] = [(entry[0], entry[1])]
                        else:
                            """If a name DOES exist in the current version of the short-term dns names dict (but it doesn't
                               contain the exact timestamp we currently have), we should UPDATE it so we can write it to
                               the file.
                            """
                            if (entry[0], entry[1]) not in self.short_term_pdns_dict[flow_ip]:
                                self.short_term_pdns_dict[flow_ip] += [(entry[0], entry[1])]
                continue
            if self.utils.is_streaming: # only do this for streaming logic
                pickle.dump(self.short_term_pdns_dict, stpdf_handle) # at the end, (over)write pickle file with our current knowledge


    def collect_local_lookups(self):
        """This function parses the questions dictionary and collects the destination ports and timestamps for all of
           the lookups that are either local forward lookups:
               questions["hello.local."]=[("44332", "1234.5678", "10.17.18.24")]
           or local reverse lookups:
               questions["5.15.168.192.in-addr.arpa."]=[("55117", "2345.6789", "hi.local.")]
           These are collected in a list and returned to the caller.

           Some testing examples for local forward and local reverse lookups:
           questions["hello.local."]=[("51317", "1234.5678", "10.17.18.24"),("54217", "1235.7789", "172.16.18.40")]
           questions["5.15.168.192.in-addr.arpa."]=[("8675", "1245.5432", "hi.local.")]
        """

        local_lookups = []
        names = self.questions.keys()
        for name in names:
            if len(self.questions[name]) == 0:
                continue
            for entry in self.questions[name]:  # iterate through all resolutions for a given DNS name
                dest_port = entry[0]
                resolution = entry[2]
                # remove local forward lookups
                if re.match(self.utils.local_ips_forward_regex, resolution):
                    local_lookups += [dest_port + " or "]
                # remove local reverse lookups
                else:
                    if re.match(self.utils.local_ips_reverse_regex, name):
                        local_lookups += [dest_port + " or "]
        # remove extra " or " from end of list
        if len(local_lookups) > 0:
            last = local_lookups.pop()
            local_lookups += [last[:-4]]
        return local_lookups
