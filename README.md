# networksage
This repository contains publicly-released tools that will be helpful when interacting with the NetworkSage platform. Note that all functionality inside will require either a free or paid API key. To request an API key, please register for an account at https://networksage.seclarity.io/register.

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
```
sudo apt-get install libpcap-dev
```

To install the `networksage` package, simply type the following:
```
pip install networksage
```


## Available Modules

There are multiple modules available within this package. Details about each are below.

### A. API Wrappers
**module name:** `wrappers`

With the release of our public APIs, all of the information available in the UI (and more!) is now available directly via API call.
To import this module into your project, type the following:
```
from networksage_tools.wrappers import wrappers
```
From there, each of the following APIs can be called via the mentioned wrapper.

#### Available APIs

Regardless whether or not you use this package, the following APIs are available to users:

##### 1. Sample Upload
**Endpoint URL:** `https://api.seclarity.io/upload/v1.0/uploader`

Takes one of our [supported file formats](#supported-file-formats), uploads it to NetworkSage (to your private view, if you are a paying customer), and converts it into our Secflow format.

**Relevant Wrapper:** `upload_sample`


##### 2. List of Uploaded Samples
**Endpoint URL:** `https://api.seclarity.io/upload/v1.0/uploads/list`

Lists information about all files you have uploaded.

**Relevant Wrapper:** `list_my_samples`


##### 3. Get Sample Metadata for Private Sample
**Endpoint URL:** `https://api.seclarity.io/sec/v1.0/samples/<sample_uuid>`

Lists high-level metadata about a particular sample. It does not provide the enriched data.

**Relevant Wrapper:** `get_private_sample_metadata`

##### 4. Get Secflows for Private Sample
**Endpoint URL:** `https://api.seclarity.io/sec/v1.0/samples/<sample_uuid>/list`

Returns all Secflows from the sample identified via UUID.

**Relevant Wrapper:** `get_secflows_from_sample`

##### 5. Get Secflows for Public Sample
**Endpoint URL:** `https://ns-genericservice.app.seclarity.io/public/secflows/v1/<sample_public_uuid>/list/aggregated`

Returns all Secflows from the sample identified via a public UUID. A public UUID will be generated for any samples uploaded that are not set to private. Note that this endpoint also provides an aggregated view of **all** sample contents, not just Secflows.

**Relevant Wrapper:** `get_secflows_from_sample`

##### 6. Get Global Count for Secflow
**Endpoint URL:** `https://api.seclarity.io/sec/v1.0/secflows/<flowid>/count`

Returns the number of global samples a given Secflow has been observed in. This can be easily used to understand how common some kind of activity to a particular Destination is globally.

**Relevant Wrapper:** `get_global_count_for_secflow`

##### 7. Get Metadata about a Destination
**Endpoint URL:** `https://api.seclarity.io/sec/v1.0/destinations/<destination_name:port>`

Returns any metadata we know for the particular Destination. This can include:
* Title
* Description
* Relevance
* Tags

The list above will likely expand over time. For additional details about what each type of metadata above means, please refer to our [glossary](https://www.seclarity.io/resources/glossary/).

**Use Cases:**
- Has anyone seen a site I've seen?
- Does the community know that a site is **not interesting**? **known malicious**?
- What category is this Destination associated with?

**Relevant Wrapper:** `get_destination_for_secflow`

##### 8. Get Metadata about a Behavior
**Endpoint URL:** `https://api.seclarity.io/sec/v1.0/behaviors/<flowid>`

Returns any metadata we know for this particular flow category to this Destination. Included metadata:
* Title
* Description
* Relevance
* Tags

**Use Cases:**
- Has someone tagged this with an `Impact` tag of `CredentialsEntered`?
- Is this Behavior to this site indicative of a domain being parked?
- Is this Behavior known to be a Microsoft portal loading?

**Relevant Wrapper:** `get_behavior_for_secflow`

##### 9. Get Metadata about an Event
**Endpoint URL:** `https://api.seclarity.io/sec/v1.0/events/<eventid>`

Returns any metadata we know for this particular Event (made up of two or more Behaviors). Included metadata:
* Title
* Description
* Relevance
* Tags

**Use Cases:**
- Is this Event known to be associated with a link click on a URL Shortener?
- Has someone tagged this with a `Threat` tag of `Phishing`?
- Is this Event indicative of a domain being parked?

**Relevant Wrapper:** `get_event_for_secflow`

### B. Streaming Secflow Collector
**module name:** `streaming`

This module allows you to directly capture network traffic as unenriched Secflows (Secflows without flow category labels). This is beneficial for a number of reasons:

* Secflows are *extremely* lightweight, so you can actually do this continuously in the background without affecting system performance (i.e. you can collect network telemetry continuously on your endpoints)!
* Secflows have no identifying data, so you can avoid worrying about accidentally leaking information (URIs, passwords, keys, etc...)

To import this module into your project, type the following:
```
from networksage_tools.streaming import streaming
```
From there, each of the following APIs can be called via the mentioned wrapper.
#### Usage

To capture Secflows continuously using this module from your project, enter the following (note that you'll need to be root to capture packets):

```
streaming.start(<interface_name>, <duration_in_seconds>) 
```
Note that the above will run in perpetuity, capturing packets from the interface you specified (such as "enp0s3" on Ubuntu systems). Every time the specified duration you provided is reached (if you provide no value, it defaults to 300 seconds), a sample will be created and uploaded to your NetworkSage account.


## Other Useful Information
### Helper Functions
This repository contains several helper functions to make it easier to perform common actions with the platform more easily.

1. `get_aggregated_data_for_sample` wraps the API endpoints for public and private samples to return data identically, since the endpoints provide data differently.

2. `get_uuid_for_uploaded_sample` makes it easy to get back either the public or private UUID for a sample. Samples that are public have both a public and a private UUID, while those that are private have only the latter. All later sample analysis requires one of these UUIDs.

3. `wait_for_sample_processing` polls the platform to identify when the data is ready to be reviewed. A sample will generally take somewhere between 30 and 90 seconds to be processed by the system (depending on load, size of sample, etc...).


### Supported File Formats

NetworkSage currently supports uploading the following files (which will be converted into our Secflow format):

* PCAP
* PCAPNG
* Zeek (conn.log and dns.log)
* Secflow

If you have a format that you'd like us to support, please review our [FAQs](https://www.seclarity.io/resources/faqs/) and contact `support at seclarity [.] io`.

### Getting Involved
We have **a lot** of plans to change the face of security. If you want to be involved as a contributor or to be a part of the community we're building, we highly encourage you to join our [Slack](https://join.slack.com/t/networksage/shared_invite/zt-yr8qv3xe-eqc8vEui9q0GV_LWH8vw6w)!


### License
This software is provided under the Apache Software License. See the accompanying LICENSE file for more information.
