# VTClient - VirusTotal API Client

![Python3.7 badge](https://img.shields.io/badge/python-v3.7-blue)


# Requirements & Install

    Python3
    (inside of a virutalenv) pip3 install .
        - will install requests package as requirement


# Usage

    Method name     Description

    search          Search VT and get all hashes from the search
    search2         Search VT using intelligence link, will be slower but will not use as much api key
    report          Get a single report
    reports         Get multiple reports
    genreports      Get multiple reports using a generator
    download        Download a list of hashes
    gendownload     Download a list of hashes using a generator


# Examples

    from vtclient import VTClient

    vtclient = VTClient("VTPRIAVATEKEY")

    hashlist = vtclient.search("tag:peexe or pedll tag:trusted positives:0")

    for page_reports in vtclient.reports(hashlist):
        #do stuff with reports
        for hashval, report in page_reports.items():
            print(hashval)
            print(json.dumps(report, indent=4))
    
    vtclient.download(hashlist)
    
    

