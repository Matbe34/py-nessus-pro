import json, requests, re, sys
from datetime import datetime
from selenium import webdriver
from bs4 import BeautifulSoup
from loguru import logger

from py_nessus_pro.scan import _Scan

# file deepcode ignore SSLVerificationBypass: Nessus self-signed certificate
requests.packages.urllib3.disable_warnings() 

class PyNessusPro:
    
    nessus_server = ""
    headers = {}
    config = {}
    folder_map = {}
    policy_map = {}
    scans = {}

    def __init__(self, nessus_server: str, username: str, password: str, log_level: str = "warning"):
        
        self.headers = {}
        self.folder_map = {}
        self.policy_map = {}
        self.scans = {}
        
        self.nessus_server = nessus_server if not self.nessus_server else self.nessus_server
        if not self.headers:
            self.headers = {
                "Content-Type" : "application/json", 
                "User-Agent":"Mozilla/5.0 Gecko/20100101 Firefox/114.0"
            }

            r = requests.get(self.nessus_server, headers=self.headers, verify=False)
            html = r.text
            
            soup = BeautifulSoup(html, 'html.parser')
            script_urls = []
            for script in soup.find_all('script', src=True):
                script_urls.append(script['src'])
            options = webdriver.ChromeOptions()
            options.add_argument('ignore-certificate-errors')
            options.add_argument('headless=new')
            options.add_argument('disable-gpu')
            options.add_argument('no-sandbox')
            options.page_load_strategy = 'eager'
            options.headless = True
            driver = webdriver.Chrome(options=options)
            driver.get(self.nessus_server)
            for script_url in script_urls:
                driver.execute_script(f'var xhr = new XMLHttpRequest(); xhr.open("GET", "{script_url}", false); xhr.send(null); eval(xhr.responseText);')
                token = driver.execute_script('return _Utils.getApiToken();')
                if token:
                    break
            driver.quit()
            
            r = requests.post(f"{self.nessus_server}/session", headers=self.headers, data=f'{{"username":"{username}","password":"{password}"}}', verify=False)
            if r.status_code == 200:
                self.headers["X-Cookie"] = "token=" + json.loads(r.text)["token"]
                self.headers["X-API-Token"] = token
                logger.info("Successfully logged in")
            else:
                raise Exception("[!] Login failed")
        
        if len(self.folder_map) == 0:
            folders = json.loads(requests.get(f"{self.nessus_server}/folders", headers=self.headers, verify=False).text)
            if not folders.get("folders", None):
                logger.warning("No folders found.")
            for folder in folders["folders"]:
                self.folder_map[folder["name"]] = folder["id"]
            logger.info("Found %d custom folders." % (len(self.folder_map) - 2))

        if len(self.policy_map) == 0:
            policies = json.loads(requests.get(f"{self.nessus_server}/policies", headers=self.headers, verify=False).text)
            if policies.get("policies", None):
                for policy in policies["policies"]:
                    self.policy_map[policy["name"]] = policy["id"]
                logger.info("Found %d custom policies." % len(self.policy_map))
            else:
                logger.info("No policies found")

        if not self.scans:
            scans_list = json.loads(requests.get(f"{self.nessus_server}/scans", headers=self.headers, verify=False).text)
            if scans_list.get("scans", None):
                for scan in scans_list["scans"]:
                    if scan["folder_id"] != 2:
                        folder = next((key for key, value in self.folder_map.items() if value == scan["folder_id"]), None)
                        self.scans[scan["id"]] = _Scan(self.nessus_server, self.headers, self.folder_map, self.policy_map, id = scan["id"], name = scan["name"], folder = folder)

    def new_scan(self, name: str = "", targets: str = "", folder: str = "", create_folder: bool = True):
        if folder:
            if not folder in self.folder_map and create_folder:
               self.create_folder(folder)
        scan = _Scan(self.nessus_server, self.headers, self.folder_map, self.policy_map, 
                    name=name, targets=targets, folder=folder)
        self.scans[scan.id] = scan
        return scan.id
    
    def list_scans(self):
        return [f"{scan_id} - {scan.get_name()}" for scan_id, scan in self.scans.items()]
    
    def get_scan_launch_ids(self):
        return list(self.scans.keys())
    
    def get_scan_ids(self):
        return list(self.scans.keys())
    
    def get_scan_metadata(self, scan_id: int):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        return self.scans[scan_id].get_metadata()
    
    def get_scan_status(self, scan_id: int):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        return self.scans[scan_id].get_status()

    def set_scan_name(self, scan_id: int, name: str):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        self.scans[scan_id].set_name(name)

    def set_scan_description(self, scan_id: int, description: str):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        self.scans[scan_id].set_description(description)

    def set_scan_folder(self, scan_id: int, folder: str):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        self.scans[scan_id].set_folder(folder)

    def set_scan_policy(self, scan_id: int, policy: str):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        self.scans[scan_id].set_policy(policy)

    def set_scan_target(self, scan_id: int, target: str):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        self.scans[scan_id].set_target(target)

    def set_scan_launch_now(self, scan_id: int, launch_now: bool):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        self.scans[scan_id].set_launch_now(launch_now)

    def set_scan_live_results(self, scan_id: int, live_results: str):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        self.scans[scan_id].set_live_results(live_results)

    def set_scan_program_scan(self, scan_id: int, enabled: bool, date: str):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        self.scans[scan_id].set_program_scan(enabled, date)

    def post_scan(self, scan_id: int):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        
        scan = self.scans[scan_id]
        old_id = scan.id
        new_id = scan.post() 
        
        if old_id != new_id:
            self.scans[new_id] = self.scans.pop(old_id)
            
        return new_id

    def pause_scan(self, scan_id: int):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        
        # check if scan is running
        if self.scans[scan_id].get_status()["status"] != "running":
            raise ValueError(f"Scan ID {scan_id} is not running")

        return self.scans[scan_id].pause()

    def resume_scan(self, scan_id: int):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        
        # check if scan is paused
        if self.scans[scan_id].get_status()["status"] != "paused":
            raise ValueError(f"Scan ID {scan_id} is not paused")

        return self.scans[scan_id].resume()

    def stop_scan(self, scan_id: int):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        
        if self.scans[scan_id].get_status()["status"] not in ["running", "pending", "resuming"]:
            raise ValueError(f"Scan ID {scan_id} is not running, pending or resuming")

        return self.scans[scan_id].stop()

    def force_stop_scan(self, scan_id: int):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        
        return self.scans[scan_id].force_stop()

    def dump_scans(self):
        scans = []
        for scan in self.scans.values():
            scans.append(scan.dump())
        return scans

    def get_scan_reports(self, scan_id: int, path: str = ""):
        if scan_id not in self.scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        return self.scans[scan_id].get_reports(path)
    
    def get_status_by_name(self, name: str):
        res = []
        ids = self.search_scans(name)
        for id in ids:
            res.append({"name":self.scans[id].get_name(), "status":self.scans[id].get_status()})
        return res
    
    def get_reports_by_name(self, name: str, path: str):
        res = []
        ids = self.search_scans(name)
        for id in ids:
            res.append({"id": id, "name":self.scans[id].get_name(), "path":self.scans[id].get_reports(path)})
        return res
    
    def get_scans_before(self, before: str):
        res = []
        ids = self.search_scans(before = before)
        for id in ids:
            res.append({"id": id, "name":self.scans[id].get_name(), "status":self.scans[id].get_status()})
        return res
    
    def get_scans_after(self, after: str):
        res = []
        ids = self.search_scans(after = after)
        for id in ids:
            res.append({"id": id, "name":self.scans[id].get_name(), "status":self.scans[id].get_status()})
        return res
    
    def search_scans(self, name: str = "", after: str = "", before: str = ""):
        results = []
        for scan_id, scan in self.scans.items():
            if name:
                name = re.sub(r'(?<!\.)\*', '.*', name)
                if re.compile(name, re.IGNORECASE).search(scan.get_name()):
                    if after:
                        after_millis = datetime.strptime(after, "%Y-%m-%d_%H:%M:%S").timestamp()
                        if after_millis < scan.get_status()["scan_start"]:
                            if before:
                                before_millis = datetime.strptime(before, "%Y-%m-%d_%H:%M:%S").timestamp()
                                if before_millis > scan.get_status()["scan_start"]:
                                    results.append(scan_id)
                            else:
                                results.append(scan_id)
                    else:
                        results.append(scan_id)
            elif after:
                after_millis = datetime.strptime(after, "%Y-%m-%d_%H:%M:%S").timestamp()
                if after_millis < scan.get_status()["scan_start"]:
                    if before:
                        before_millis = datetime.strptime(before, "%Y-%m-%d_%H:%M:%S").timestamp()
                        if before_millis > scan.get_status()["scan_start"]:
                            results.append(scan_id)
                    else:
                        results.append(scan_id)  
            elif before:
                before_millis = datetime.strptime(before, "%Y-%m-%d_%H:%M:%S").timestamp()
                if before_millis > scan.get_status()["scan_start"]:
                    results.append(scan_id)                 

        return results
    
    def create_folder(self, folder_name: str):
        if folder_name in self.folder_map:
            logger.warn("Folder already exists")
            return self.folder_map[folder_name]
        else:
            r = requests.post(f"{self.nessus_server}/folders", headers=self.headers, data=f'{{"name":"{folder_name}"}}', verify=False)
            if r.status_code == 200:
                self.folder_map[folder_name] = json.loads(r.text)["id"]
                logger.success("Folder created")
                return self.folder_map[folder_name]
            else:
                logger.error("[!] Folder creation failed")

    def import_policy(self, policy_file):
        with open(policy_file, "r") as f:
            headers = self.headers.copy()
            headers.pop("Content-Type")
            r = requests.post(f"{self.nessus_server}/file/upload", headers=headers, files={"Filedata":f}, verify=False)
            if r.status_code == 200:
                logger.info("Policy uploaded")
                filename = json.loads(r.text)["fileuploaded"]
                r = requests.post(f"{self.nessus_server}/policies/import", headers=self.headers, data=f'{{"file":"{filename}"}}', verify=False)
                if r.status_code == 200:
                    policy_id = json.loads(r.text)["id"]
                    policy_name = json.loads(r.text)["name"]
                    self.policy_map[policy_name] = policy_id
                    logger.success(f"Policy imported, {policy_name}")
                else:
                    logger.error("Policy import failed")
            else:
                logger.error("Policy import failed")
    
    def import_scan(self, scan_path, folder_name = ""):
        with open(scan_path, "r") as f:
            headers = self.headers.copy()
            headers["Content-Type"] = "multipart/form-data"
            r = requests.post(f"{self.nessus_server}/file/upload", headers=headers, files={"Filedata":f}, verify=False)
            if r.status_code == 200:
                logger.info("Scan uploaded")
                filename = json.loads(r.text)["fileuploaded"]
                if folder_name:
                    if folder_name in self.folder_map:
                        folder_id = self.folder_map[folder_name]
                    else:
                        logger.info("Folder not found, creating it")
                        folder_id = self.create_folder(folder_name)
                else:
                    folder_id = 2
                r = requests.post(f"{self.nessus_server}/scans/import", headers=self.headers, data=f'{{"file":"{filename}", "folder_id":{folder_id}}}', verify=False)
                if r.status_code == 200:
                    scan_name = json.loads(r.text)["name"]
                    logger.success(f"Scan imported, {scan_name}")
                else:
                    logger.error("Scan import failed")
            else:
                logger.error("Scan import failed")

