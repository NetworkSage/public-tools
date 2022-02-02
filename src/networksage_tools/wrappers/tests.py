"""
    Copyright (c) 2022 David Pearson (david@seclarity.io)
    Date: 01/31/2022
    This file contains wrappers and helper functions for various NetworkSage APIs.

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.
"""

import time
import pathlib
from datetime import datetime
import importlib.resources
from networksage_tools.wrappers import wrappers as wrapper

def run_tests(api_key):
    test_dir = None
    with importlib.resources.path(__package__, "tests") as p:
        test_dir = p
    print("Testing List:")
    res = wrapper.list_my_samples()
    print("Found", str(len(res)), "samples")

    print("Testing Secflow upload")
    print("File should be within", test_dir)
    sample_name = "secflow_test.sf"
    sample_location = pathlib.PurePath(test_dir, sample_name)
    with open(sample_location, 'rb') as indata:
        sample_data = indata.read()
    sample_type = "secflow"
    result = wrapper.upload_sample(sample_name, sample_data, sample_type)
    print("Result is", result.text)

    print("Testing PCAP upload")
    sample_name = "pcap_test.pcap"
    sample_location = pathlib.PurePath(test_dir, sample_name)
    with open(sample_location, 'rb') as indata:
        sample_data = indata.read()
    sample_type = "pcap"
    result = wrapper.upload_sample(sample_name, sample_data, sample_type)
    print("Result is", result.text)

    print("Testing Zeek upload without DNS log")
    sample_name = "test_conn.log"
    sample_location = pathlib.PurePath(test_dir, sample_name)
    with open(sample_location, 'rb') as indata:
        sample_data = indata.read()
    sample_type = "zeek"
    result = wrapper.upload_sample(sample_name, sample_data, sample_type)
    print("Result is", result.text)

    print("Testing Zeek upload with DNS log")
    sample_name = "test_conn.log"
    dnslog_name = "test_dns.log"
    dnslog_location = pathlib.PurePath(test_dir, dnslog_name)
    sample_location = pathlib.PurePath(test_dir, sample_name)
    with open(sample_location, 'rb') as indata:
        sample_data = indata.read()
    with open(dnslog_location, 'rb') as dns_indata:
        dns_data = dns_indata.read()
    sample_type = "zeek"
    result = wrapper.upload_sample(sample_name, sample_data, sample_type, dns_data=dns_data)
    print("Result is", result.text)

    now = time.time()
    now_utc = datetime.timestamp(datetime.utcfromtimestamp(now))

    print("Testing UUID finder for last private uploaded sample")
    upload_time = now_utc
    result = wrapper.get_uuid_for_uploaded_sample(sample_name, upload_time)
    if result is not None:
        private_uuid = result
        print("Success, got private UUID", private_uuid)
    else:
        print("Failed!")
        private_uuid = None

    print("Waiting for sample to be processed...")
    wrapper.wait_for_sample_processing(private_uuid)
    print("Sample", private_uuid, "successfully processed!")

    print("Testing UUID finder for last public uploaded sample")
    result = wrapper.get_uuid_for_uploaded_sample(sample_name, upload_time, get_public_uuid=True)
    public_uuid = None
    if result is not None:
        public_uuid = result
        print("Success, got public UUID", public_uuid)
    else:
        print("Failed!")

    print("Trying to get just Secflows from private sample:")
    result = wrapper.get_secflows_from_sample(private_uuid)
    if result is not None:
        print("Success, got", str(len(result)), "Secflows")
    else:
        print("Failed!")

    print("Trying to get just Secflows from public sample:")
    result = wrapper.get_secflows_from_sample(public_uuid, is_public=True)
    if result is not None:
        print("Success, got", str(len(result)), "Secflows")
    else:
        print("Failed!")
    if len(result) >= 2:
        example_secflow = result[1]
    else:
        print("Result is short. Can't continue tests.")
        return

    print("===================================\nChanging to known public/private secflow IDs for remaining tests.\n===================================")
    public_uuid = "NzhmZjIxMWMtMjZjNi00OGZjLTgwM2UtYzNmZWM3MmNjOTU0I2hhc2gjMDBkYzM5N2MzZjg1NDcyYjljN2Y0MjAzYzQwOGU0ZmI="
    private_uuid = "00dc397c3f85472b9c7f4203c408e4fb"
    print("Note that any of the private UUID calls will fail unless you are the owner.")
    time.sleep(2)

    print("Trying to get just Secflows from private sample:")
    result = wrapper.get_secflows_from_sample(private_uuid)
    if result is not None:
        print("Success, got", str(len(result)), "Secflows")
    else:
        print("Failed!")

    print("Trying to get just Secflows from public sample:")
    result = wrapper.get_secflows_from_sample(public_uuid, is_public=True)
    if result is not None:
        print("Success, got", str(len(result)), "Secflows")
    else:
        print("Failed!")
    example_secflow = result[1]

    print("Trying to get just count for second secflow from public sample:")
    count = wrapper.get_global_count_for_secflow(example_secflow, public_uuid, is_public=True)
    if count != -1:
        print("Success, count is", str(count))
    else:
        print("Failed!")
    print("Trying to get just count for second secflow from private sample:")
    count = wrapper.get_global_count_for_secflow(example_secflow, private_uuid)
    if count != -1:
        print("Success, count is", str(count))
    else:
        print("Failed!")
    print("Trying to get event metadata for third secflow from public sample:")
    example_secflow = result[2]
    event = wrapper.get_event_for_secflow(example_secflow, public_uuid, is_public=True)
    if event is not None:
        print("Success:", event)
    else:
        print("Failed!")
    print("Trying to get event metadata for third secflow from private sample:")
    example_secflow = result[2]
    event = wrapper.get_event_for_secflow(example_secflow, private_uuid)
    if event is not None:
        print("Success:", event)
    else:
        print("Failed!")
    print("Trying to get behavior metadata for thirteenth secflow from public sample:")
    example_secflow = result[12]
    behavior = wrapper.get_behavior_for_secflow(example_secflow, public_uuid, is_public=True)
    if behavior is not None:
        print("Success:", behavior)
    else:
        print("Failed!")
    print("Trying to get behavior metadata for thirteenth secflow from private sample:")
    example_secflow = result[12]
    behavior = wrapper.get_behavior_for_secflow(example_secflow, private_uuid)
    if behavior is not None:
        print("Success:", behavior)
    else:
        print("Failed!")
    print("Trying to get destination metadata for fourteenth secflow from public sample:")
    example_secflow = result[13]
    dest = wrapper.get_destination_for_secflow(example_secflow, public_uuid, is_public=True)
    if dest is not None:
        print("Success:", dest)
    else:
        print("Failed!")
    print("Trying to get destination metadata for fourteenth secflow from private sample:")
    example_secflow = result[13]
    dest = wrapper.get_destination_for_secflow(example_secflow, private_uuid)
    if dest is not None:
        print("Success:", dest)
    else:
        print("Failed!")
    print("Trying to get aggregated metadata for public sample:")
    agg = wrapper.get_aggregated_data_for_sample(public_uuid, is_public=True)
    if agg is not None:
        print("Success. Found", str(len(agg)), "activities!")
    else:
        print("Failed!")
    print("Trying to get aggregated metadata for private sample:")
    agg = wrapper.get_aggregated_data_for_sample(private_uuid)
    if agg is not None:
        print("Success. Found", str(len(agg)), "activities!")
    else:
        print("Failed!")