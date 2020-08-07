import hashlib
import os

from urllib.parse import urlparse, parse_qs

from modutils.aio import aioloop
from modutils.http import BaseSession

class VTClient(BaseSession):
    def __init__(self, vtkey:str, *args:list, **kwargs:dict):
        super().__init__(*args, **kwargs)
        self.vtkey = vtkey
        self.headers.update({'x-apikey': vtkey})
        self.max_async_pool = 16


    def report(self, hashval: str, allinfo: int= 1) -> dict:
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {"apikey" : self.vtkey, "resource" : hashval, "allinfo" : allinfo}
        response = self.get(url, params=params)
        return {hashval: response.json() if response.status_code == 200 else response.status_code}

    def reports(self, hashlist: list, allinfo: int= 1) -> dict:
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        resource_chunk = 24
        resource_groups = [
            ",".join(hashlist[index : index + resource_chunk]) 
            for index in range(0, len(hashlist), resource_chunk)
        ]
        calls = [
            [url, {'params': {"apikey" : self.vtkey, "resource" : group, "allinfo" : allinfo}}]
            for group in resource_groups
        ]
        all_reports = {}
        for response in aioloop(self.get, calls):
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
            yield self.reports(hashlist[index:index+self.max_async_pool], allinfo)
        
    def old_search(self, query, maxresults=None) -> list:
        hashes = []
        url = "https://www.virustotal.com/vtapi/v2/file/search"
        data = {"apikey" : self.vtkey, "query" : query}
        while True:
            resp = self.post(url, data=data)
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
    

    def search(self, query:str= None, hashes: list=[], descriptors_only: bool=True, maxresults: int=None) -> list:
        if not query and not hashes:
            print('Error: no input given to search')
            return []
        url = "https://www.virustotal.com/api/v3/intelligence/search"
        search_content = []
        query = query or '\n'.join(hashes)
        data = {"query" : query, "descriptors_only":descriptors_only, "limit":300}
        headers = {"x-apikey": self.vtkey}
        nextpage = url
        while nextpage:
            resp = self.get(nextpage, params=data, headers=headers)
            if resp.status_code == 200:
                content = resp.json()
                if descriptors_only:
                    search_content.extend([d.get('id') for d in content.get('data', []) if d.get('type') == 'file'])
                else:
                    search_content.extend([{d.get('id'): d} for d in content.get('data', []) if d and d.get('type') == 'file'])
                if maxresults:
                    if len(search_content) >= maxresults:
                        return search_content[:maxresults]
                nextpage = content.get('links', {}).get('next') if content.get('links', {}).get('next') != nextpage else None
            else:
                nextpage = None
        return search_content
    
    
    def search2(self, query, maxresults=None) -> list:
        hashes = []
        url = "https://www.virustotal.com/intelligence/search/programmatic/"
        params = {"apikey" : self.vtkey, "query" : query}
        while True:
            resp = self.get(url, params=params)
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

    def _download(self, hashval: str, download_directory):
        url = "https://www.virustotal.com/vtapi/v2/file/download"
        params = {'apikey': self.vtkey, 'hash': hashval}
        response = self.get(url, params=params)
        if response.status_code == 200:
            hashval = urlparse(response.url).path[1:]
            check = self._integrity(response.content)
            if check.upper() == hashval.upper():
                with open(os.path.join(download_directory, hashval), 'wb') as fout:
                    fout.write(response.content)
                return {hashval: 'SUCCESS'}
            else:
                return {hashval: 'FAILED INTEGRITY CHECK'}
        elif response.status_code == 404:
            hashval = parse_qs(urlparse(response.url).query).get('hash', [])
            if hashval and len(hashval) > 0:
                return {hashval[0]: 'NOT FOUND'}

    def download(self, hashlist: list, download_directory: str= 'downloads') -> list:
        download_directory = os.path.realpath(download_directory)
        if not os.path.exists(download_directory):
            os.makedirs(download_directory)
        hlc = [[[hv, download_directory]] for hv in hashlist]
        return aioloop(self._download, hlc)
    

    def generate_downloads(self, hashlist):
        for index in range(0, len(hashlist), self.max_async_pool):
            yield self.download(hashlist[index:index+self.max_async_pool])