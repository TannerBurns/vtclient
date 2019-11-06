# VTClient - VirusTotal API Client

![MIT badge](https://img.shields.io/badge/license-MIT-black)
![Python3.7 badge](https://img.shields.io/badge/python-v3.7-blue)


# Requirements

    - Python3.7+
    - pip3

# Installation

    pip3 install .
    - Recommend installing within a virtual environment

# Usage

    Method name         Description

    search              Search VT and get all hashes from the search
    search2             Search VT using intelligence link, will be slower but will not use as much api key
    report              Get a single report
    reports             Get multiple reports
    generate_reports    Get multiple reports using a generator
    download            Download a list of hashes
    generate_download   Download a list of hashes using a generator


# Examples

    from vtclient import VTClient

    vtclient = VTClient("VTPRIVATEKEY")

    hashlist = vtclient.search("tag:peexe or pedll tag:trusted positives:0")

    reports = vtclient.reports(hashlist)
    
    vtclient.download(hashlist)
    
    

