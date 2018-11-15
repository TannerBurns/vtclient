# VtClient - Python3

# Requirements

    Python3 - requests

# Usage

    Search - search VT and get all hashes from the search

    Download - Download a list of hashes

    Reports - Get reports for a list of hashes
        'reports' function is a generator to conserve memory

# Examples

    from VtClient import VtClient

    vtclient = VtClient("VTPRIAVATEKEY")

    hashlist = vtclient.search("tag:peexe or pedll tag:trusted positives:0")

    for reports in vtclient.reports(hashlist):
        #do stuff with reports
        for hashval, report in report:
            print(hashval)
            print(json.dumps(report, indent=4))
    
    vtclient.download(hashlist)
    
    

