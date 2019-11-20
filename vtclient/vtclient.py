import asyncio
import hashlib
import json
import os

from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Callable, Tuple, List
from urllib.parse import urlparse, parse_qs

from vast.requests import VastSession

class VTClient(VastSession):
    def __init__(self, vtkey:str, download_directory:str="downloads", *args:list, **kwargs:dict):
        super().__init__(*args, **kwargs)
        self.vtkey = vtkey
        self.download_directory = os.path.join(self.basepath, download_directory)

    def report(self, hashval: str, allinfo: int= 1) -> dict:
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {"apikey" : self.vtkey, "resource" : hashval, "allinfo" : allinfo}
        response = self.session.get(url, params=params)
        return {hashval: response.json() if response.status_code == 200 else response.status_code}
    
    def reports(self, hashlist: list, allinfo: int= 1) -> dict:
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        resource_chunk = 24
        resource_groups = [
            ",".join(hashlist[index : index + resource_chunk]) 
            for index in range(0, len(hashlist), resource_chunk)
        ]
        calls = [
            (['get', url], {'params': {"apikey" : self.vtkey, "resource" : group, "allinfo" : allinfo}})
            for group in resource_groups
        ]
        all_reports = {}
        for response in self.bulk_requests(calls):
            if response.status_code == 200:
                report_response = response.json()
                if type(report_response) == dict:
                    all_reports.update({report_response.get('sha256', report_response.get('resource')):report_response})
                elif type(report_response) == list:
                    all_reports.update(
                        {report.get('sha256', report.get('resource')):report 
                        for report in report_response}
                    )
        return all_reports
        
    
    def generate_reports(self, hashlist: list, allinfo: int= 1) -> dict:
        for index in range(0, len(hashlist), self.max_async_pool):
            yield reports(hashlist[index:index+self.max_async_pool], allinfo)
        
    def search(self, query, maxresults=None) -> list:
        hashes = []
        url = "https://www.virustotal.com/vtapi/v2/file/search"
        data = {"apikey" : self.vtkey, "query" : query}
        while True:
            resp = self.session.post(url, data=data)
            if resp.status_code == 200:
                res = resp.json()
                hashes.extend(res.get("hashes", []))
                if not res.get("offset"):
                    break
                if maxresults:
                    if len(hashes) >= maxresults:
                        break
                data.update({"offset": res.get("offset")})
        if maxresults:
            return hashes[:maxresults]
        else:
            return hashes
    
    def search2(self, query, maxresults=None) -> list:
        hashes = []
        url = "https://www.virustotal.com/intelligence/search/programmatic/"
        params = {"apikey" : self.vtkey, "query" : query}
        while True:
            resp = self.session.get(url, params=params)
            if resp.status_code == 200:
                res = resp.json()
                hashes.extend(res.get("hashes", []))
                if not res.get("next_page"):
                    break
                if maxresults:
                    if len(hashes) >= maxresults:
                        break
                params.update({"page": res.get("next_page")})
        if maxresults:
            return hashes[:maxresults]
        else:
            return hashes
    
    def _integrity(self, content) -> str:
        return hashlib.sha256(content).hexdigest() 

    def download(self, hashlist) -> list:
        if not os.path.exists(self.download_directory):
            os.makedirs(self.download_directory)
        url = "https://www.virustotal.com/intelligence/download/"
        calls = [
            (['get', url], {'params': {'apikey': self.vtkey, 'hash': hashval}})
            for hashval in hashlist
        ]
        results = []
        for index in range(0, len(calls), self.max_async_pool):
            bulk_responses = self.bulk_requests(calls[index:index+self.max_async_pool])
            for response in bulk_responses:
                if response.status_code == 200:
                    hashval = urlparse(response.url).path[1:]
                    check = self._integrity(response.content)
                    if check.upper() == hashval.upper():
                        with open(f'{self.download_directory}/{hashval}', 'wb') as fout:
                            fout.write(response.content)
                        results.append({hashval: 'SUCCESS'})
                    else:
                        results.append({hashval: 'FAILED INTEGRITY CHECK'})
                elif response.status_code == 404:
                    hashval = parse_qs(urlparse(response.url).query).get('hash', [])
                    if hashval and len(hashval) > 0:
                        results.append({hashval[0]: 'NOT FOUND'})
        return results

    def generate_downloads(self, hashlist):
        for index in range(0, len(hashlist), self.max_async_pool):
            yield download(hashlist[index:index+self.max_async_pool])