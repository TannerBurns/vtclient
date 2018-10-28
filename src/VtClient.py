import requests
import asyncio
import concurrent.futures
import json
import functools

class VtClient:
    def __init__(self, vtkey):
        self.session = requests.Session()
        rqAdapters = requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=20, max_retries=2)
        self.session.mount("https://", rqAdapters)
        self.session.headers.update({
                "Accept-Encoding": "gzip, deflate",
                "User-Agent" : "gzip,  My Python requests library example client or username"
        })
        self.vtkey = vtkey
    

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
        reports = {}
        resource_groups = [",".join(hashlist[ind:ind+RESOURCE_CHUNK]) for ind in range(0, len(hashlist), RESOURCE_CHUNK)]
        for ind in range(0, len(resource_groups), CHUNK):
            group = resource_groups[ind:ind+CHUNK]
            reports.update(loop.run_until_complete(self._yield_reports(group)))
        return reports





    