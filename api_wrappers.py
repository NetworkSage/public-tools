"""
    Copyright (c) 2022 David Pearson (david@seclarity.io)
    Date: 01/30/2022
    This file contains wrappers and other helper functions for the current version of public APIs available to users of
    NetworkSage. To request an API key, please register for an account at https://networksage.seclarity.io/register.

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.
"""

import requests
import json
import threading
import os
import time
import base64
from datetime import datetime
import concurrent.futures
from tests import tests

my_api_key_var = "NETWORKSAGE_API_KEY"
api_key = os.environ.get(my_api_key_var)
if api_key is None:
    print("Missing API Key. Please type export NETWORKSAGE_API_KEY='<your_api_key>' in your terminal to set up.")


def had_error(response):
    """Quick error handling function to avoid code repetition.
    """

    if response.status_code != requests.codes.ok:
        print("Error:", response.text)
        return True
    json_data = json.loads(response.text)
    if json_data["error"]:
        print("Error:", json_data["body"])
        return True
    return False


def upload_sample(sample_name, sample_data, sample_type, dns_data=None):
    """Upload a sample to the NetworkSage platform.
        + sample_name: whatever you want the sample to be named in the platform
                        (for your own reference and/or public reference, depending on privacy settings).
        + sample_data: data for the sample in binary format (such as through
                        opening in "rb" mode and reading into this variable).
        + sample_type: one of the accepted upload types (pcap, pcapng, zeek, secflow, currently)
        + dns_data: an optional field (currently valid for Zeek only) that allows DNS information to be passed along.

        Return data will contain status codes (result.status_code), and JSON-encoded information (in result.text)
        containing:
            + error: Boolean identifying if there was an error
            + body: a message about acceptance of the sample
    """

    upload_url = "https://api.seclarity.io/upload/v1.0/uploader"

    if dns_data is not None and sample_type == "zeek":
        files = { "file": (sample_name
                            , sample_data
                            , "application/octet-stream"
                            )
                , "zeekDnsFile": ("dns_" + sample_name
                                    , dns_data
                                    , "application/octet-stream"
                                    )
                }
    else:
        files = { "file": (sample_name
                            , sample_data
                            , "application/octet-stream"
                            )
                }
    request_headers = { "apikey": api_key }

    request_data = { "type": sample_type
                    , "fileName": sample_name
                    }
    result = requests.post(upload_url
                            , headers=request_headers
                            , files=files
                            , data=request_data
                            )
    return result


def list_my_samples():
    """High-level information about each of the samples that you have uploaded.
        Return data will contain status codes (result.status_code), and JSON-encoded information (in result.text)
        containing:
            + error: Boolean identifying if there was an error
            + body: a list of samples identifying (among other info):
                    + filename: name of file provided to NetworkSage
                    + processed: boolean identifying if samples has been
                                processed completely
                    + fullS3FilePath: path to the file
                    + dateCreated: string (in DD/MM/YYYY HH:MM:SS format)
                                identifying when the sample was created in the system (a.k.a. uploaded)
                    + dateProcessed: string (in "YYYY-MM-DDTHH:MM:SS.mmmmmm"
                                format) identifying when the file has been successfully processed. This will not exist
                                if processed is False
                    + fileType: string identifying what type of file it is
                                (i.e. pcap)
                    + uuid: string uniquely identifying this sample in
                            NetworkSage
    """

    list_url = "https://api.seclarity.io/upload/v1.0/uploads/list"

    request_headers = { "apikey": api_key }
    result = requests.get(list_url, headers=request_headers)
    if had_error(result):
        return None
    result_json = json.loads(result.text)
    list_of_samples = result_json["body"]
    return list_of_samples


def get_uuid_for_uploaded_sample(sample_name, upload_time_utc, get_public_uuid=False):
    """Wraps a couple of APIs to help a user find a sample that has been
        uploaded at a (roughly) known time. Expects the upload_time to be in epoch time as an integer.
    """

    files_list = list_my_samples()
    if files_list is None:
        return files_list

    uuid = None
    time_format = "%Y-%m-%dT%H:%M:%S.%f"
    for file_info in files_list:
        try:
            if file_info["fileName"] == sample_name:
                # grab exact time this file was uploaded from file path
                sample_uploaded_time_utc_str = (file_info["fullS3FilePath"].split("date=")[1]).split("/")[0]
                sample_uploaded_time_utc = int(
                    datetime.timestamp(datetime.strptime(sample_uploaded_time_utc_str
                                    , time_format
                                    )
                                )
                            )
                if abs(sample_uploaded_time_utc - upload_time_utc) < 60:
                    uuid = file_info["uuid"]
                    if not get_public_uuid:
                        break
                    else:
                        sample_metadata = get_private_sample_metadata(uuid)
                        if sample_metadata is not None:
                            while True:
                                if "id" in sample_metadata.keys() and "hash" in sample_metadata.keys():
                                    str_bytes = (sample_metadata["id"]
                                                + "#hash#"
                                                + sample_metadata["hash"]
                                                ).encode("ascii")

                                    uuid = base64.b64encode(str_bytes).decode("ascii")
                                    break
                                else:
                                    time.sleep(5.0) # check every 5 seconds to see if it's done processing
                        else:
                            print("Couldn't find requested sample's public uuid!")
                            uuid = None
                    break
        except:
            continue # ignore malformed items, if they exist
    if uuid is None:
        print("Couldn't find requested sample!")
    return uuid


def get_private_sample_metadata(uuid):
    """Returns high-level information about a private sample (that you own) by
        its UUID. Relevant information returned:
        + dateCreated: time string in format of DD/MM/YYYY HH:MM:SS
        + fileName: string produced by NetworkSage. Will not be the same as the
                    name provided in the front-end.
        + trafficDate: string version of the epoch time (floating-point) that
                    corresponds to when the traffic was actually captured (if your sample is from 2 weeks ago, this will
                    identify that time).
        When the trafficDate value is populated, that means that the sample was successfully processed. Otherwise that
        value will be empty.
    """
    sample_id = uuid

    endpoint_url = "https://api.seclarity.io/sec/v1.0/samples/" + sample_id
    request_headers = { "apikey": api_key }
    result = requests.get(endpoint_url, headers=request_headers)

    if had_error(result):
        return None
    result_json = json.loads(result.text)
    sample_metadata = result_json["body"]
    return sample_metadata


def is_sample_processed(uuid):
    """Wrapper to determine if a sample (whose UUID is passed in) is processed.
    """
    is_processed = False
    sample_metadata = get_private_sample_metadata(uuid)
    if sample_metadata is not None and sample_metadata["trafficDate"] != "":
        is_processed = True
    return is_processed


def wait_for_sample_processing(uuid):
    """Wrapper to poll until sample has been processed. When this returns, the sample will be ready.
    """
    sample_checking_timer = threading.Event()
    while not sample_checking_timer.wait(15.0): # check every 15 seconds
        if is_sample_processed(uuid):
            sample_checking_timer.set()
            break


def get_public_sample_data(uuid, metadata_type=None, individual_flow_id=None):
    """Wrapper that returns just the requested metadata type for a public
        sample.
    """
    endpoint_url = "https://ns-genericservice.app.seclarity.io/public/secflows/v1/" + uuid + "/list/aggregated"
    result = requests.get(endpoint_url)
    if had_error(result):
        return None
    result_json = json.loads(result.text)
    aggregated_activities = result_json["body"]
    if metadata_type is None:
        return aggregated_activities

    metadata = []
    for activity in aggregated_activities:
        if individual_flow_id is not None:
            if activity["secflow"]["flowId"] == individual_flow_id:
                return activity[metadata_type]
            else:
                continue
        metadata += [activity[metadata_type]]
    return metadata


def get_secflows_from_sample(uuid, is_public=False):
    """Returns all secflows from the sample identified via UUID. For each
        secflow returned, the following relevant information will be present (each as a string):
        + destinationBytes: number of bytes seen from the destination
        + destinationData: destination name (or IP, if no name known) with port
                        number appended
        + destinationNameSource: how the destinationData field was populated
                            (cache [from a cache maintained by NetworkSage], passive [from this sample], active [from a
                            reverse lookup], or original [name provided or no name known])
        + destinationPackets: number of packets seen from the destination
        + duration: number of seconds (string representation of a float) this
                    secflow was active
        + flowCategory: which category this activity belongs to (see
                        https://www.seclarity.io/resources/glossary/ for details)
        + flowId: way to identify communication to this destination with this flowCategory across NetworkSage
        + relativeStart: number of seconds (string representation of float)
                    into the sample this particular secflow began happening
        + sourceBytes: number of bytes seen from the source
        + sourceData: source name (generally an IP unless provided) with port
                    number appended
        + sourcePackets: number of packets seen from the source
    """
    if is_public:
        all_secflows = get_public_sample_data(uuid, "secflow")
        return all_secflows
    else:
        endpoint_url = "https://api.seclarity.io/sec/v1.0/samples/"+uuid+"/list"
        request_headers = { "apikey": api_key }
        result = requests.get(endpoint_url, headers=request_headers)
    if had_error(result):
        return None

    result_json = json.loads(result.text)
    all_secflows = []
    for aggregated_activity in result_json["body"]:
        #print("Activity:", aggregated_activity)
        all_secflows += [aggregated_activity]

    return all_secflows


def get_global_count_for_secflow(secflow, uuid=None, is_public=False, session=None):
    """Returns the number of global samples a given Secflow has been observed
        in. If for some reason there is no response, returns -1. Session variable can be passed in if many counts are
        being requested simultaneously (to reduce overhead).
    """
    count = -1
    flowid = secflow["flowId"]

    if is_public:
        count = get_public_sample_data(uuid, "flowIdCount", flowid)
        return count

    endpoint_url = "https://api.seclarity.io/sec/v1.0/secflows/" + flowid + "/count"
    request_headers = { "apikey": api_key }

    if session is None:
        result = requests.get(endpoint_url, headers=request_headers)
    else:
        result = session.get(endpoint_url, headers=request_headers)

    if had_error(result):
        return count
    result_json = json.loads(result.text)
    count = result_json["body"]
    return count


def get_destination_for_secflow(secflow, uuid=None, is_public=False, session=None):
    """Returns a Destination (see https://www.seclarity.io/resources/glossary/
        for details) for a given Secflow. If no Destination exists, returns None. Session variable can be passed in if
        many Destinations are being requested simultaneously (to reduce overhead).
    """
    destination = None
    name = secflow["destinationData"]

    if is_public:
        flowid = secflow["flowId"]
        destination = get_public_sample_data(uuid
                                            , "destination"
                                            , flowid
                                            )
        return destination

    endpoint_url = "https://api.seclarity.io/sec/v1.0/destinations/" + name
    request_headers = { "apikey": api_key }

    if session is None:
        result = requests.get(endpoint_url, headers=request_headers)
    else:
        result = session.get(endpoint_url, headers=request_headers)

    if had_error(result):
        return destination
    result_json = json.loads(result.text)
    destination = result_json["body"]
    return destination


def get_behavior_for_secflow(secflow, uuid=None, is_public=False, session=None):
    """Returns a Behavior (see https://www.seclarity.io/resources/glossary/ for
        details) for a given Secflow. If no Behavior exists, returns None. Session variable can be passed in if many
        Behaviors are being requested simultaneously (to reduce overhead).
    """
    behavior = None
    flowid = secflow["flowId"]
    if is_public:
        behavior = get_public_sample_data(uuid
                                        , "behavior"
                                        , flowid
                                        )
        return behavior

    endpoint_url = "https://api.seclarity.io/sec/v1.0/behaviors/" + flowid
    request_headers = { "apikey": api_key }

    if session is None:
        result = requests.get(endpoint_url, headers=request_headers)
    else:
        result = session.get(endpoint_url, headers=request_headers)

    if had_error(result):
        return behavior
    result_json = json.loads(result.text)
    behavior = result_json["body"]
    return behavior


def get_event_for_secflow(secflow, uuid=None, is_public=False, session=None):
    """Returns an Event (see https://www.seclarity.io/resources/glossary/ for
        details) that includes a given Secflow. If no Event exists, returns None. Session variable can be passed in if
        many Events are being requested simultaneously (to reduce overhead).
    """
    event = None
    if "eventId" not in secflow:
        return event
    eventid = secflow["eventId"]
    if is_public:
        flowid = secflow["flowId"]
        event = get_public_sample_data(uuid
                                        , "event"
                                        , flowid
                                        )
        return event

    endpoint_url = "https://api.seclarity.io/sec/v1.0/events/" + eventid
    request_headers = { "apikey": api_key }

    if session is None:
        result = requests.get(endpoint_url, headers=request_headers)
    else:
        result = session.get(endpoint_url, headers=request_headers)

    if had_error(result):
        return event
    result_json = json.loads(result.text)
    event = result_json["body"]
    return event


def get_aggregated_data_for_sample(uuid, is_public=False):
    """Wrapper that returns an aggregated view of all of the Secflows, Counts,
        Destinations, Behaviors, and Events for a given sample. These will be ordered by relativeStart time with respect
        to the sample.
    """
    aggregated_activity = []
    if is_public:
        aggregated_activity = get_public_sample_data(uuid)
    else:
        secflows = get_secflows_from_sample(uuid, is_public)
        if secflows is None:
            return secflows

        # set up aggregated activity list for population
        for secflow in secflows:
            aggregated_activity += [{"secflow": secflow
                                , "destination": {}
                                , "behavior": {}
                                , "event": {}
                                , "flowIdCount": 1 # default value that should ALWAYS be overwritten
                                }]
        calls = [{
                       "activities": aggregated_activity
                       , "metadata_type": "count"
                        }
                ,{
                       "activities": aggregated_activity
                       , "metadata_type": "destination"
                        }
                ,{
                       "activities": aggregated_activity
                       , "metadata_type": "behavior"
                       }
                ,{
                       "activities": aggregated_activity
                       , "metadata_type": "event"
                       }
                ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            for call_args in calls:
                executor.submit(retrieve_via_session, call_args)
    return aggregated_activity


def retrieve_via_session(call_args):
    """Helper that uses sessions (instead of individual requests per item) to
        collect many of the same items in a row. Helps to reduce overhead.
    """
    activities = call_args["activities"]
    metadata_type = call_args["metadata_type"]

    session = requests.Session()
    if metadata_type == "count":
        for activity in activities:
            count = get_global_count_for_secflow(activity["secflow"]
                                                , session=session
                                                )
            if count == -1:
                print("Error! This is a bug! Please file a ticket with dev@seclarity.io")
                continue
            activity["flowIdCount"] = count
    elif metadata_type == "destination":
        for activity in activities:
            d = get_destination_for_secflow(activity["secflow"]
                                            , session=session
                                            )
            if d is None:
                continue
            activity["destination"] = d
    elif metadata_type == "behavior":
        for activity in activities:
            b = get_destination_for_secflow(activity["secflow"]
                                            , session=session
                                            )
            if b is None:
                continue
            activity["behavior"] = b
    elif metadata_type == "event":
        for activity in activities:
            e = get_destination_for_secflow(activity["secflow"]
                                            , session=session
                                            )
            if e is None:
                continue
            activity["event"] = e
    else:
        print("Unrecognized metadata type", metadata_type+". Exiting!")
        sys.exit(1)

if __name__ == "__main__":
    # Do some tests
    tests.run_tests(api_key)