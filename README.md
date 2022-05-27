# networksage-tools
This repository contains publicly-released tools that will be helpful when interacting with the NetworkSage platform. Note that to upload anything to NetworkSage, you will require either a free or paid API key. To request an API key, please register for an account at https://networksage.seclarity.io/register.

## What is NetworkSage?

The NetworkSage platform, first and foremost, acts as a lightweight, privacy-maintaining enrichment layer for your network traffic. It takes network flows (which we call *Secflows*), categorizes them with one of a couple dozen labels (see our [Glossary](https://www.seclarity.io/resources/glossary/) for details), and compares them with the global dataset of known activity. For every Secflow, it returns:
  * how common it is globally
  * which categorization it has
  * any metadata the security community has provided

To visually illustrate, refer to the following (taken from a public [sample](https://networksage.seclarity.io/public/samples/NzhmZjIxMWMtMjZjNi00OGZjLTgwM2UtYzNmZWM3MmNjOTU0I2hhc2gjYjZhMzQ4MTk0NTU5NDFiNWE1MGYzMzM4Nzc5N2YwZDY=) we found while creating our first [Threat Report](https://www.seclarity.io/resources/blog/the-art-of-perswaysion-phishing-kit/)).

When this sample was uploaded to NetworkSage, all Secflows were automatically categorized and their global commonality was identified:

![Flow Categories and Commonality](https://gitlab.com/networksage-public-tools/networksage/-/raw/main/images/flow_cat_commonality.png?raw=true)

In addition, many of those **Destinations** (an IP or Domain name plus its port) had additional metadata provided by the security community. That information was made available inline:

![Destinations with Metadata](https://gitlab.com/networksage-public-tools/networksage/-/raw/main/images/destinations_metadata.png?raw=true)

Some of the categories associated with certain Secflows also indicated specific **Behavior** was happening. That information (also provided by the community) was shared for more in-depth knowledge:

![Behaviors with Metadata](https://gitlab.com/networksage-public-tools/networksage/-/raw/main/images/behaviors_metadata.png?raw=true)

Finally, some of the Behaviors (when seen in a particular order within some period of time) actually identified more complex interactions that we call **Events**:

![Events with Metadata](https://gitlab.com/networksage-public-tools/networksage/-/raw/main/images/events_metadata.png?raw=true)

## Installation

Note that this package requires `libpcap-dev` to be installed on your system. Please use your system's package manager (such as `apt` on Ubuntu) to install `libpcap-dev`:
```bash
sudo apt-get install libpcap-dev
```

While Windows isn't yet supported due to issues with underlying libraries (specifically `pcapy`), we'd welcome anyone who wants to document the steps to make it work. At the very minimum, you will need the following:
```
A C++ compiler. Microsoft Visual Studio Build Tools is known to work.
Npcap's SDK, which is a replacement for the WinPCAP developer's kit.
```


To install the `networksage-tools` package, simply type the following:
```bash
pip install networksage-tools
```


## Available Modules

There are multiple modules available within this package. Details about each are below.

### A. Streaming Secflow Collector
**module name:** `streaming`

This module allows you to directly capture network traffic as unenriched Secflows (Secflows without flow category labels). This is beneficial for a number of reasons:

* Secflows are *extremely* lightweight, so you can actually do this continuously in the background without affecting system performance (i.e. you can collect network telemetry continuously on your endpoints)!
* Secflows have no identifying data, so you can avoid worrying about accidentally leaking information (URIs, passwords, keys, etc...)

To import this module into your project, type the following:
```python3
from networksage_tools.streaming import streaming
```

#### Usage

To capture Secflows continuously using this module from your project, enter the following (note that you'll need to be root to capture packets):

```python3
streaming.start(<interface_name>, <duration_in_seconds>, <optional_verbosity>) 
```
Note that the above will run in perpetuity, capturing packets from the interface you specified (such as "enp0s3" on Ubuntu systems). Every time the specified duration you provided is reached (if you provide no value, it defaults to 300 seconds), a sample will be created and uploaded to your NetworkSage account. Providing the optional `is_verbose` value will print a small amount of information about the number of flows and its UUID.

### B. Standalone Converter
**module name:** `converter`

This module allows you to convert captured network traffic from any of our supported formats (currently PCAP, PCAPNG, and Zeek) into unenriched Secflows (Secflows without flow category labels). This is useful if you already have network telemetry that you'd like to upload to NetworkSage, but you don't want to upload the original file (for privacy, size, or other reasons).

To import this module into your project, type the following:
```python3
from networksage_tools.converter import convert
```

#### Usage

To convert a PCAP or PCAPNG file into an unenriched Secflow file, simply enter the following:

```python3
convert.convert_pcap(<path_to_pcap_file>) 
```

To convert a Zeek Conn log into an unenriched Secflow file, simply enter the following:

```python3
convert.convert_zeek(<path_to_conn_log>, <optional_path_to_dns_log>) 
```
If you have (and would like to include) DNS information that was captured by Zeek, provide the `dns.log` in addition to the `conn.log`. Naming will be much enhanced by doing so.

`NOTE:`
As of v1.0.0 of this package, we now support Zeek files in [JSON](https://docs.zeek.org/en/master/log-formats.html#zeek-json-format-logs) and plaintext [TSV](https://docs.zeek.org/en/master/log-formats.html#zeek-tsv-format-logs) (i.e. the OG) formats. If you are uploading plaintext logs, please make sure that your `conn.log` files have the following fields in the following order (_Field #_ lines are annotations for clarity below and should *NOT* be included in the file):
```json
        Field #  1       2        3                 4               5
                ts      uid     id.orig_h       id.orig_p       id.resp_h
        Field #    6             7        8        9               10
                id.resp_p       proto   service duration        orig_bytes
        Field #     11              12              13              14
                resp_bytes      conn_state      local_orig      local_resp
        Field #     15             16      17               18             19
                missed_bytes    history orig_pkts       orig_ip_bytes  resp_pkts
        Field #       20              21
                resp_ip_bytes   tunnel_parents

    An example of a flow line from the conn log is as follows ("field #" lines are my annotation):

        Field #       1                        2                      3
                1601060272.439360       CC9S3G178KjzSMTGRk      192.168.100.224
        Field #   4             5        6       7       8          9
                 137    192.168.100.255 137     udp     dns     12.114023
        Field #  10     11    12      13     14      15      16       17
                1186    0     S0      -       -       0       D       23
        Field #  18     19      20      21
                1830    0       0       -
```

For `dns.log` files (again, if you're *not* using JSON), make sure that the file matches the following:

```json
   Field #       1       2          3               4               5               6             7         8
                ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   trans_id

   Field #       9       10        11               12             13         14           15        16
                rtt     query    qclass         qclass_name       qtype   qtype_name      rcode   rcode_name

   Field #      17      18      19      20      21        22         23        24
                AA      TC      RD      RA      Z       answers     TTLs    rejected

   Note that all field names are not used. If you do not have a field, please give it an appropriate default
   value as defined by the Zeek format (https://docs.zeek.org/en/master/logs/dns.html).
```

## Supported File Formats

NetworkSage currently supports uploading the following files (which will be converted into our Secflow format):

* PCAP
* PCAPNG
* Zeek (conn.log and dns.log in TSV or JSON formatting; see prior section for details)
* Secflow

If you have a format that you'd like us to support, please review our [FAQs](https://www.seclarity.io/resources/faqs/) and contact `support at seclarity [.] io`.

## Getting Involved
We have **a lot** of plans to change the face of security. If you want to be involved as a contributor or to be a part of the community we're building, we highly encourage you to join our [Slack](https://join.slack.com/t/networksage/shared_invite/zt-yr8qv3xe-eqc8vEui9q0GV_LWH8vw6w)!


## License
This software is provided under the Apache Software License. See the accompanying LICENSE file for more information.
