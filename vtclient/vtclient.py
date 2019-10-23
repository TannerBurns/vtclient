import asyncio
import hashlib
import json
import os

from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Callable, Tuple

import requests


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
    
    async def execute_request(self, req_fn, **kwargs):
        return req_fn(**kwargs)

    async def get(self, url:str, headers:dict=None, params:dict=None, data:dict=None, json:dict=None):
        kwargs = {'url': url, 'headers': headers, 'params': params, 'data': data, 'json': json}
        return await self.execute_request(self.session.get, **kwargs)
    
    async def post(self, url:str, headers:dict=None, params:dict=None, data:dict=None, json:dict=None, files:dict=None):
        kwargs = {'url': url, 'headers': headers, 'params': params, 'data': data, 'json': json, 'files': files}
        return await self.execute_request(self.session.post, **kwargs)

    async def _bulk_request(self, req_fn:Callable, args:list):
        return [
            await req_fn(*a) 
            for i in range(0, len(args), self.num_workers)
            for a in args[i:i+self.num_workers]
        ]

    def multirequest(self, req_fn:Callable, args:list):
        '''multirequest -- run requests function in bulk
        
           req_fn   -- {Callable} function to run in bulk
           args -- {list} arguments to be distributed to function

           return -- list of results from function
        '''
        self.loop = asyncio.new_event_loop()
        return self.loop.run_until_complete(self._bulk_request(req_fn, args))


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
        rsrc_chunk = 24
        resource_groups = [[",".join(hashlist[ind:ind+rsrc_chunk]), allinfo] for ind in range(0, len(hashlist), rsrc_chunk)]
        responses = self.multirequest(self.report, resource_groups)
        return  {res.get('sha256'):res for r in responses if r.status_code == 200 for res in r.json()}
    
    def genreports(self, hashlist: list, allinfo: int= 1):
        rsrc_chunk = 24
        resource_groups = [[",".join(hashlist[ind:ind+rsrc_chunk]), allinfo] for ind in range(0, len(hashlist), rsrc_chunk)]
        for ind in range(0, len(resource_groups), self.num_workers):
            group = resource_groups[ind:ind+self.num_workers]
            responses = self.multirequest(self.report, group)                      
            yield {res.get('sha256'):res for r in responses if r.status_code == 200 for res in r.json()}
  
    def search(self, query, maxresults=None):
        hashes = []
        url = "https://www.virustotal.com/vtapi/v2/file/search"
        data = {"apikey": self.vtkey, "query": query}
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
    
    def search2(self, query, maxresults=None):
        hashes = []
        url = "https://www.virustotal.com/intelligence/search/programmatic/"
        params = {"apikey": self.vtkey, "query": query}
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
    
    def _integrity(self, content):
        hasher = hashlib.sha256(content)
        return hasher.hexdigest()

    async def _download(self, *hashval):
        hashval = ''.join(hashval)
        url = "https://www.virustotal.com/intelligence/download/"
        params = {"apikey":self.vtkey, "hash": hashval}
        resp = self.session.get(url, params=params)
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
