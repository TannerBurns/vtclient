import requests
import asyncio
import concurrent.futures
import json
import functools
import os

class VtClient:
    def __init__(self, vtkey, dlDirectory="downloads"):
        self.session = requests.Session()
        rqAdapters = requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=20, max_retries=2)
        self.session.mount("https://", rqAdapters)
        self.session.headers.update({
                "Accept-Encoding": "gzip, deflate",
                "User-Agent" : "gzip,  My Python requests library example client or username"
        })
        self.vtkey = vtkey
        self.dlDir = dlDirectory
    

    def report(self, hashval):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {"apikey": self.vtkey, "resource": hashval, "allinfo":1}
        return self.session.get(url, params=params)
    
    async def _yield_reports(self, hashlist):
        responses = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            loop = asyncio.get_event_loop()
            futures = [
                loop.run_in_executor(
                    executor,
                    functools.partial(self.report, hashlist[ind])
                )
            for ind in range(0, len(hashlist)) if hashlist[ind]]
        
        await asyncio.gather(*futures)

        for ind in range(0, len(futures)):
            resp = futures[ind].result()
            if resp.status_code == 200:
                responses.update({hashlist[ind]: resp.json()})
            else:
                responses.update({hashlist[ind]: "ERROR"})
        
        return responses
    
    def reports(self, hashlist):
        CHUNK = 16
        RESOURCE_CHUNK = 24
        loop = asyncio.get_event_loop()
        resource_groups = [",".join(hashlist[ind:ind+RESOURCE_CHUNK]) for ind in range(0, len(hashlist), RESOURCE_CHUNK)]
        for ind in range(0, len(resource_groups), CHUNK):
            group = resource_groups[ind:ind+CHUNK]
            resp = {}
            for k,v in loop.run_until_complete(self._yield_reports(group)).items():
                if len(k.split(",")) > 1:
                    for r in v:
                        resp.update({r.get("sha256"):r})
                else:
                    resp.update({k:v})
            yield resp

    
    def search(self, query, maxresults=None):
        hashes = []

        url = "https://www.virustotal.com/vtapi/v2/file/search"
        params = {"apikey": self.vtkey, "query": query}
        while True:
            resp = self.session.post(url, data=params)
            if resp.status_code == 200:
                res = resp.json()
                hashes.extend(res.get("hashes"))
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
            resp = self.session.get(url, params=params)
            if resp.status_code == 200:
                res = resp.json()
                hashes.extend(res.get("hashes"))
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

    def dl(self, hashval):
        url = "https://www.virustotal.com/intelligence/download/"
        params = {"apikey":self.vtkey, "hash": hashval}
        resp = self.session.get(url, params=params)
        if resp.status_code == 200:
            with open("downloads/{0}".format(hashval), "wb") as fout:
                fout.write(resp.content)
    
    async def _yield_downloads(self, hashlist):
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            loop = asyncio.get_event_loop()
            futures = [
                loop.run_in_executor(
                    executor,
                    functools.partial(self.dl, hashlist[ind])
                )
            for ind in range(0, len(hashlist)) if hashlist[ind]]
        
        await asyncio.gather(*futures)

    def download(self, hashlist):
        CHUNK = 16
        loop = asyncio.get_event_loop()
        if not os.path.exists(self.dlDir):
            os.makedirs(self.dlDir)
        for ind in range(0, len(hashlist), CHUNK):
            group = hashlist[ind:ind+CHUNK]
            loop.run_until_complete(self._yield_downloads(group))




    