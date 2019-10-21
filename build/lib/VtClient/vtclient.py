import requests
import asyncio
import json
import os
import hashlib

from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Callable, Tuple


class BaseAsyncClient(object):
    def __init__(self, workers: int= 16, *args: list, **kwargs: dict):
        self.num_workers = workers
        self.session = requests.Session()
        rqAdapters = requests.adapters.HTTPAdapter(
            pool_connections = workers, 
            pool_maxsize = workers + 4, 
            max_retries=3
        )
        self.session.mount("https://", rqAdapters)
        self.session.mount('http://', rqAdapters)
        self.session.headers.update({
                "Accept-Encoding": "gzip, deflate",
                "User-Agent" : "gzip,  Python Asyncio Requests Client"
        })
        self.basepath = os.path.realpath(os.getcwd())
    
    def get(self, url:str, headers:dict=None, params:dict=None, data:dict=None, json:dict=None):
        return self.session.get(url, headers=headers, params=params, data=data, json=json)
    
    def post(self, url:str, headers:dict=None, params:dict=None, data:dict=None, json:dict=None, files:dict=None):
        return self.session.post(url, headers=headers, params=params, data=data, json=json, files=files)
    
    async def _bulk_request(self, req_fn:Callable, *args:list):
        with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
            futures = [self.loop.run_in_executor(executor, partial(req_fn, *a)) for a in args if a]
            await asyncio.gather(*futures)
            return [f.result() for f in futures]
    
    def multirequest(self, req_fn:Callable, *args:list):
        '''multirequest -- run requests function in bulk
        
           req_fn   -- {Callable} function to run in bulk
           args -- {list} arguments to be distributed to function

           return -- list of results from function
        '''
        self.loop = asyncio.new_event_loop()
        return self.loop.run_until_complete(self._bulk_request(req_fn , *args))


class VtClient(BaseAsyncClient):
    def __init__(self, vtkey:str, download_directory:str="downloads", *args:list, **kwargs:dict):
        super().__init__(*args, **kwargs)
        self.vtkey = vtkey
        self.download_directory = os.path.join(self.basepath, download_directory)

    def report(self, hashval: str, allinfo: int= 1):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {"apikey": self.vtkey, "resource": hashval, "allinfo":allinfo}
        return self.get(url, params=params)
    
    def reports(self, hashlist: list, allinfo: int= 1):
        RESOURCE_CHUNK = 24
        self.loop = asyncio.new_event_loop()
        resource_groups = [",".join(hashlist[ind:ind+RESOURCE_CHUNK]) for ind in range(0, len(hashlist), RESOURCE_CHUNK)]
        responses = self.multirequest(self.report, (resource_groups, allinfo))
        return  {res.get('sha256'):res for r in responses if r.status_code == 200 for res in r.json()}
    
    def genreports(self, hashlist: list, allinfo: int= 1):
        RESOURCE_CHUNK = 24
        self.loop = asyncio.new_event_loop()
        resource_groups = [",".join(hashlist[ind:ind+RESOURCE_CHUNK]) for ind in range(0, len(hashlist), RESOURCE_CHUNK)]
        for ind in range(0, len(resource_groups), self.num_workers):
            group = resource_groups[ind:ind+self.num_workers]
            responses = self.multirequest(self.report, (group, allinfo))                      
            yield {res.get('sha256'):res for r in responses if r.status_code == 200 for res in r.json()}
  
    def search(self, query, maxresults=None):
        hashes = []
        url = "https://www.virustotal.com/vtapi/v2/file/search"
        params = {"apikey": self.vtkey, "query": query}
        while True:
            resp = self.post(url, data=params)
            if resp.status_code == 200:
                res = resp.json()
                hashes.extend(res.get("hashes", []))
                if not res.get("offset"):
                    break
                if maxresults:
                    if len(hashes) >= maxresults:
                        break
                params.update({"offset": res.get("offset")})
        if maxresults:
            return hashes[:maxresults]
        else:
            return hashes
    
    def search2(self, query, maxresults=None):
        hashes = []
        url = "https://www.virustotal.com/intelligence/search/programmatic/"
        params = {"apikey": self.vtkey, "query": query}
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
    
    def _integrity(self, content):
        hasher = hashlib.sha256(content)
        return hasher.hexdigest()

    def _download(self, hashval):
        url = "https://www.virustotal.com/intelligence/download/"
        params = {"apikey":self.vtkey, "hash": hashval}
        resp = self.get(url, params=params)
        if resp.status_code == 200:
            check = self._integrity(resp.content)
            if check.upper() == hashval.upper():
                with open(f'{self.download_directory}/{hashval}', 'wb') as fout:
                    fout.write(resp.content)
                return {hashval: 'SUCCESS'}
            else:
                return {hashval: 'ERROR - integrity check'}
        else:
            return {hashval: f'ERROR - status code {resp.status_code}'}        

    def download(self, hashlist):
        if not os.path.exists(self.download_directory):
            os.makedirs(self.download_directory)
        return self.multirequest(self._download, hashlist)

    def gendownload(self, hashlist):
        if not os.path.exists(self.download_directory):
            os.makedirs(self.download_directory)
        for ind in range(0, len(hashlist), self.num_workers):
            yield self.multirequest(self._download, hashlist[ind:ind+self.num_workers])
