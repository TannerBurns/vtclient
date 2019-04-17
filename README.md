# VtClient - Python3

# Requirements

    Python3 - requests

# Usage

    Search - search VT and get all hashes from the search
    
    Search2 - search VT using intelligence link, will be slower but will not use as much api key

    Download - Download a list of hashes

    Reports - Get reports for a list of hashes
        'reports' function is a generator to conserve memory

# Examples

    from src.VtClient import VtClient

    vtclient = VtClient("VTPRIAVATEKEY")

    hashlist = vtclient.search("tag:peexe or pedll tag:trusted positives:0")

    for reports in vtclient.reports(hashlist):
        #do stuff with reports
        for hashval, report in reports:
            print(hashval)
            print(json.dumps(report, indent=4))
    
    vtclient.download(hashlist)
    
    

