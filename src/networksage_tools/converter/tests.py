"""
    Copyright (c) 2022 David Pearson (david@seclarity.io)
    Date: 02/03/2022
    This file contains tests for the converter code.

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.
"""

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
                    }
                ]
    test_dir = None
    with importlib.resources.path(__package__, "tests") as p:
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
    print("Tests complete! Compare tests in", outputs_location, "to those in", expected_outputs_location, "to determine if any issues have occurred.")