import asyncio
import hashlib
import json
import os

from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Callable, Tuple
from urllib.parse import urlparse, parse_qs

import requests

class AioRequests(object):
    def __init__(self, workers: int= 16, *args: list, **kwargs: dict):
        self.workers = workers
        self.session = requests.Session()
        rqAdapters = requests.adapters.HTTPAdapter(
            pool_connections = workers, 
            pool_maxsize = workers+4, 
            max_retries = 3
        )
        self.session.mount("https://", rqAdapters)
        self.session.mount('http://', rqAdapters)
        self.session.headers.update({
                "Accept-Encoding": "gzip, deflate",
                "User-Agent" : "gzip,  Python Asyncio Requests Client"
        })
        self.basepath = os.path.realpath(os.getcwd())

    async def _execute(self, fn: Callable, *args: list, **kwargs: dict):
        return fn(*args, **kwargs)
    
    async def async_get(self, *args, **kwargs):
        return await self._execute(self.session.get, *args, **kwargs)
    
    async def async_post(self, *args, **kwargs):
        return await self._execute(self.session.post, *args, **kwargs)
    
    async def async_put(self, *args, **kwargs):
        return await self._execute(self.session.put, *args, **kwargs)
    
    async def async_delete(self, *args, **kwargs):
        return await self._execute(self.session.delete, *args, **kwargs)

    async def async_head(self, *args, **kwargs):
        return await self._execute(self.session.head, *args, **kwargs)

    def get(self, *args, **kwargs):
        return self.session.get(*args, **kwargs)
    
    def post(self, *args, **kwargs):
        return self.session.post(*args, **kwargs)

    def put(self, *args, **kwargs):
        return self.session.put(*args, **kwargs)
 
    def delete(self, *args, **kwargs):
        return self.session.delete(*args, **kwargs)
    
    def head(self, *args, **kwargs):
        return self.session.head(*args, **kwargs)
  
    async def _aio_executor(self, method: str, args: list):
        if method.lower() == 'get':
            return [
                await self.async_get(argtuple[0], **argtuple[1])
                for i in range(0, len(args), self.workers) 
                for argtuple in args[i:i+self.workers]
            ]
        elif method.lower() == 'post':
            return [
                await self.async_post(argtuple[0], **argtuple[1]) 
                for i in range(0, len(args), self.workers) 
                for argtuple in args[i:i+self.workers]
            ]
        elif method.lower() == 'put':
            return [
                await self.async_put(argtuple[0], **argtuple[1]) 
                for i in range(0, len(args), self.workers) 
                for argtuple in args[i:i+self.workers]
            ]
        elif method.lower() == 'delete':
            return [
                await self.async_delete(argtuple[0], **argtuple[1]) 
                for i in range(0, len(args), self.workers) 
                for argtuple in args[i:i+self.workers]
            ]
        elif method.lower() == 'head':
            return [
                await self.async_head(argtuple[0], **argtuple[1]) 
                for i in range(0, len(args), self.workers) 
                for argtuple in args[i:i+self.workers]
            ]
        else:
            raise Exception(f'Method "{method}" not supported. Choices: get, post, put, delete, head')

    def bulk_request(self, method: str, args: list):
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(self._aio_executor(method, args))



class VTClient(AioRequests):
    def __init__(self, vtkey:str, download_directory:str="downloads", *args:list, **kwargs:dict):
        super().__init__(*args, **kwargs)
        self.vtkey = vtkey
        self.download_directory = os.path.join(self.basepath, download_directory)

    def report(self, hashval: str, allinfo: int= 1):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {"apikey" : self.vtkey, "resource" : hashval, "allinfo" : allinfo}
        response = self.get(url, params=params)
        return {hashval: response.json() if response.status_code == 200 else response.status_code}
    
    def reports(self, hashlist: list, allinfo: int= 1):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        resource_chunk = 24
        resource_groups = [",".join(hashlist[index : index + resource_chunk]) for index in range(0, len(hashlist), resource_chunk)]
        calls = [(url, {'params': {"apikey" : self.vtkey, "resource" : group, "allinfo" : allinfo}}) for group in resource_groups]
        return {
            resp.get('sha256'):resp
            for responses in bulk_responses
            for resp in responses.json()
        }
    
    def generate_reports(self, hashlist: list, allinfo: int= 1):
        for index in range(0, len(hashlist), self.workers):
            yield reports(hashlist[index:index+self.workers], allinfo)
        
    def search(self, query, maxresults=None):
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
    
    def search2(self, query, maxresults=None):
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
    
    def _integrity(self, content):
        return hashlib.sha256(content).hexdigest() 

    def download(self, hashlist):
        if not os.path.exists(self.download_directory):
            os.makedirs(self.download_directory)
        url = "https://www.virustotal.com/intelligence/download/"
        calls = [(url, {'params': {'apikey': self.vtkey, 'hash': hashval}}) for hashval in hashlist]
        bulk_responses = self.bulk_request('get', calls)
        results = []
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
        for index in range(0, len(hashlist), self.workers):
            yield download(hashlist[index:index+self.workers])