"""
    Copyright (c) 2022 David Pearson (david@seclarity.io)
    Date: 02/03/2022
    This file contains tests for the converter code.

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.
"""

import json
import pathlib
import importlib.resources
from networksage_tools.converter import convert


def run_tests():
    test_cases = [
                    { "inputType": "pcapng"
                    , "filename": "testCase1_chromeWin10StartChromeBrowser.pcapng"
                    }
                    ,
                    { "inputType": "pcapng"
                    , "filename": "testCase2_chromeWin10VisitAmazonScamaDotCom.pcapng"
                    }
                    ,
                    { "inputType": "pcapng"
                    , "filename": "testCase3_onePacketNotProcessable.pcapng"
                    }
                    ,
                    { "inputType": "pcapng"
                    , "filename": "testCase4_onePacketIsProcessable.pcapng"
                    }
                    ,
                    { "inputType": "pcapng"
                    , "filename": "testCase5_oneFlowPlusDNSIsProcessable.pcapng"
                    }
                    ,
                    { "inputType": "pcap"
                    , "filename": "testCase6_icmp_plus_others.pcap"
                    }
                    ,
                    { "inputType": "zeek"
                    , "filename": "testCase7_chromeWin10StartChromeBrowser.conn.log"
                    , "hasDNS": True
                    }
                    ,
                    { "inputType": "zeek"
                    , "filename": "testCase8_chromeWin10VisitAmazonScamaDotCom.conn.log"
                    , "hasDNS": True
                    }
                    ,
                    { "inputType": "zeek"
                    , "filename": "testCase9_oneFlowNotProcessable.conn.log"
                    , "hasDNS": False
                    }
                    ,
                    { "inputType": "zeek"
                    , "filename": "testCase10_oneFlowIsProcessable.conn.log"
                    , "hasDNS": False
                    }
                    ,
                    { "inputType": "zeek"
                    , "filename": "testCase11_emptySansHeaders.conn.log"
                    , "hasDNS": False
                    }
                    ,
                    { "inputType": "zeek"
                    , "filename": "testCase12_icmp_plus_others.conn.log"
                    , "hasDNS": True
                    },
                    { "inputType": "pcap"
                    , "filename": "testCase13_mtbDotcom_bangInPlaceOfDot.pcap"
                    },
                    { "inputType": "pcap"
                    , "filename": "testCase14_faturasatacada_phish_with_nonephemeral_dport9999.pcap"
                    },
                    { "inputType": "zeek"
                        , "filename": "testCase15_chromeWin10StartChromeBrowser_JSON.conn.log"
                        , "hasDNS": True
                    }
                    ,
                    { "inputType": "zeek"
                        , "filename": "testCase16_chromeWin10VisitAmazonScamaDotCom_JSON.conn.log"
                        , "hasDNS": True
                    }
                    ,
                    { "inputType": "zeek"
                        , "filename": "testCase17_oneFlowNotProcessable_JSON.conn.log"
                        , "hasDNS": False
                    }
                    ,
                    { "inputType": "zeek"
                        , "filename": "testCase18_oneFlowIsProcessable_JSON.conn.log"
                        , "hasDNS": False
                    }
                    ,
                    { "inputType": "zeek"
                        , "filename": "testCase19_icmp_plus_others_JSON.conn.log"
                        , "hasDNS": True
                    }
                ]
    test_dir = None
    with importlib.resources.files(__package__).joinpath("tests") as p:
        test_dir = p
    inputs_location = str(pathlib.PurePath(test_dir, "inputs"))
    outputs_location = pathlib.PurePath(test_dir, "outputs")
    expected_outputs_location = pathlib.PurePath(test_dir, "expectedOutputs")

    for test in test_cases:
        try:
            if test["inputType"] in ["pcap", "pcapng"]:
                print("Converting", test["filename"], "from PCAP(NG) to Secflow.")
                convert.convert_pcap(inputs_location+"/"+test["filename"]
                                    , output_dir=outputs_location
                                    )
            elif test["inputType"] == "zeek":
                print("Converting", test["filename"], "from Zeek to Secflow.")
                if "hasDNS" in test.keys() and test["hasDNS"]:
                    dns_name = test["filename"].replace(".conn.log", ".dns.log")
                    convert.convert_zeek(inputs_location+"/"+test["filename"]
                                        , zeek_dnsfile_location=inputs_location+"/"+dns_name
                                        , output_dir=outputs_location
                                        )
                else:
                    convert.convert_zeek(inputs_location+"/"+test["filename"]
                                        , output_dir=outputs_location
                                        )
            else:
                print("Unrecognized input type", test["inputType"], "...skipping!")
                continue
            print("===============================================================")
        except:
            print("Something unexpected happened for this test case. Skipping.")
    print("Tests generation complete! Comparing secflows of tests in", outputs_location, "to those in", expected_outputs_location, "to determine if any issues have occurred.")
    diffs = 0
    for tc in test_cases:
        name = tc["filename"]
        p = pathlib.Path(name)
        if p.suffix == ".log":
            updated_name = str(p.with_suffix(".sf"))
        else:
            updated_name = p.stem + "_filtered.sf"
        print("Comparing expected vs. output for", updated_name)
        expected_loc = pathlib.PurePath(expected_outputs_location, updated_name)
        output_loc = pathlib.PurePath(outputs_location, updated_name)
        expected_data = None
        output_data = None
        try:
            with open(expected_loc, "rb") as expected:
                expected_data = json.load(expected)
            with open(output_loc, "rb") as output:
                output_data = json.load(output)
        except:
            print("Something went wrong while trying to load files. Skipping test.")
            continue
        if expected_data is None or output_data is None:
            print("Something went wrong while trying to load files. Skipping test.")
            continue

        if expected_data["trafficDate"] != output_data["trafficDate"]:
            print("Traffic dates differ: Expected",
                  expected_data["trafficDate"],
                  "vs. Output",
                  output_data["trafficDate"]
                  )
        ordered_expected = []
        for flash in expected_data["flashes"]:
            ordered_expected += [set(flash.items())]
        ordered_output = []
        for flash in output_data["flashes"]:
            ordered_output += [set(flash.items())]

        if len(ordered_expected) != len(ordered_output):
            print("Different number of secflows: Expected ("
                  + str(len(ordered_expected))
                  + ") output vs. Output ("
                  + str(len(ordered_output))
                  + ")"
                  )
        for i in range(0, len(ordered_expected)):
            try:
                if len(ordered_expected[i] ^ ordered_output[i]) != 0:
                    print("Mismatch for secflow"
                          , str(i)+": Expected"
                          , ordered_expected[i]
                          , "vs. Output"
                          , ordered_output[i]
                          )
                    diffs += 1
            except:
                print("Nothing found in position", i)
                diffs += 1
                break
    if diffs == 0:
        print("Success! No differences between expected and output!")
    else:
        print("Found", diffs, "differences between expected and output data. Please review.")

