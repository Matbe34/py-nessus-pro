import json, requests, random, string
from slugify import slugify
from datetime import datetime
from time import sleep
from loguru import logger


# file deepcode ignore SSLVerificationBypass: Nessus self-signed certificate

class _Scan():

    nessus_server = ""
    headers = {}

    export_types = {
        "nessus":"",
        "csv":"",
        "html":"vuln_by_host;compliance_exec;remediations;",
        # Disable pdf export as some Nessus installations do not support it
        # "pdf":"vuln_by_host;compliance_exec;remediations;",
    }

    def __init__(self, nessus_server: str, headers: dict, folder_map: dict, policy_map: dict, name: str = "", targets: str = "", id: str = "", folder: str = ""):
        # Generate a temporary negative ID if no ID is provided
        self.id = id if id else -int(datetime.now().timestamp())
        self.is_posted = bool(id)
        self.metadata = json.loads('''{
            "uuid":"ab4bacd2-05f6-425c-9d79-3ba3940ad1c24e51e1f403febe40",
            "settings":{
                "emails":"",
                "attach_report":"no",
                "filter_type":"and",
                "filters":[],
                "launch":"ONETIME",
                "launch_now":false,
                "enabled":false,
                "timezone":"Europe/Madrid",
                "starttime":"20231001T170000",
                "rrules":"FREQ=ONETIME",
                "live_results":"",
                "name":"NO NAME",
                "description":"",
                "folder_id":0,
                "scanner_id":"1",
                "policy_id":"0",
                "text_targets":""
            }
        }''')
        self.nessus_server = nessus_server
        self.headers = headers
        self.folder_map = folder_map
        self.policy_map = policy_map
        self.metadata["settings"]["text_targets"] = targets
        self.metadata["settings"]["name"] = name
        self.metadata["settings"]["folder_id"] = self.folder_map[folder] if folder in self.folder_map else 0
        logger.debug("Scan object created: " + str(name) + " " + str(targets))

    def set_name(self, name: str):
        self.metadata["settings"]["name"] = name
        logger.debug("Name updated: " + name)

    def set_description(self, description: str):
        self.metadata["settings"]["description"] = description
        logger.debug("Description updated: " + description)

    def set_target(self, target: str):
        self.metadata["settings"]["text_targets"] = target
        logger.debug("Target updated: " + target)

    def set_folder(self, folder: str):
        if folder in self.folder_map:
            self.metadata["settings"]["folder_id"] = self.folder_map[folder]
        else:
            raise Exception("[!] Invalid folder name: " + folder)
        logger.debug("Folder updated: " + folder)
        
    def set_policy(self, policy: str):
        if policy in self.policy_map:
            self.metadata["settings"]["policy_id"] = self.policy_map[policy]
        else:
            raise Exception("[!] Invalid policy name: " + policy)
        logger.debug("Policy updated: " + policy)
    
    def set_launch_now(self, launch: bool):
        if launch in [True, False]:
            self.metadata["settings"]["launch_now"] = launch
        else:
            raise Exception("[!] Invalid launch_now value: %s\n Value must be True or False", launch)
        logger.debug("Launch now: " + str(launch))
        
    def set_live_results(self, live_results: bool):
        if live_results in [True, False]:
            self.metadata["settings"]["live_results"] = live_results
        else:
            raise Exception("[!] Invalid live_results value: %s\n Value must be True or False", live_results)
        logger.debug("Live results: " + str(live_results))
    
    def set_program_scan(self, enabled: bool, date: str):
        if enabled in [True, False]:
            self.metadata["settings"]["enabled"] = enabled
        else:
            raise Exception("[!] Invalid enabled value: %s\n Value must be True or False", enabled)
        
        if datetime.strptime(date, "%Y%m%dT%H%M%S"):
            self.metadata["settings"]["starttime"] = date
        else:
            raise Exception("[!] Invalid date format: %s\n Format must be YYYYMMDDTHHMMSS, example: 20231001T170000", date)
        logger.debug("Program scan: " + str(enabled) + " " + date)
        
    def get_name(self):
        return self.metadata["settings"]["name"]
    
    def get_target(self):
        return self.metadata["settings"]["text_targets"]
    
    def get_folder(self):
        return self.metadata["settings"]["folder_id"]
    
    def get_policy(self):
        return self.metadata["settings"]["policy_id"]
    
    def get_description(self):
        return self.metadata["settings"]["description"]

    def get_metadata(self):
        return self.metadata
        
    def get_status(self):
        if not self.id:
            return {
                "status": "not_posted",
                "scan_start": None,
                "scan_end": None,
                "name": self.metadata["settings"]["name"]
            }

        response = requests.get(f"{self.nessus_server}/scans/{self.id}", headers=self.headers, verify=False)
        if response.status_code != 200:
            logger.error(f"Error getting scan status: {response.status_code}")
            return {
                "status": "error",
                "scan_start": None,
                "scan_end": None,
                "name": self.metadata["settings"]["name"]
            }

        x = response.json()
        if not x.get("info"):
            logger.error("Error retrieving scan status, check authorization issues or retry request.")
            return {
                "status": "error",
                "scan_start": None,
                "scan_end": None,
                "name": self.metadata["settings"]["name"]
            }

        return {
            "status": x["info"]["status"],
            "scan_start": x["info"].get("scan_start"),
            "scan_end": x["info"].get("scan_end"),
            "name": x["info"]["name"]
        }
    
    def post(self):
        if not self.metadata["settings"]["text_targets"]:
            raise Exception("[!] No targets provided")
        if self.is_posted:
            raise Exception("[!] Scan already posted")
            
        x = json.loads(requests.post(f"{self.nessus_server}/scans", headers=self.headers, json=self.metadata, verify=False).text)
        if self.metadata["settings"]["launch_now"]:
            logger.info("Scan launched: " + str(x["scan"]["id"]) + " (" + self.metadata["settings"]["name"] + ")")
        else:
            logger.info("Scan saved: " + str(x["scan"]["id"]) + " (" + self.metadata["settings"]["name"] + ")")
        
        self.id = x["scan"]["id"]
        self.is_posted = True
        return self.id

    def pause(self):
        if not self.id:
            logger.error("Scan not posted yet")
            return
        if self.get_status()["status"] != "running":
            logger.error("Scan not running")
            return
        req = requests.post(f"{self.nessus_server}/scans/{self.id}/pause", headers=self.headers, verify=False)
        if req.status_code != 200:
            logger.error("Error pausing scan: " + str(req.status_code))
            return
        logger.info("Scan paused: " + str(self.id) + " (" + self.get_name() + ")")
        return self.id
    
    def resume(self):
        if not self.id:
            logger.error("Scan not posted yet")
            return
        if self.get_status()["status"] != "paused":
            logger.error("Scan not paused")
            return
        req = requests.post(f"{self.nessus_server}/scans/{self.id}/resume", headers=self.headers, verify=False)
        if req.status_code != 200:
            logger.error("Error resuming scan: " + str(req.status_code))
            return
        logger.info("Scan resumed: " + str(self.id) + " (" + self.get_name() + ")")
        return self.id
    
    def stop(self):
        if not self.id:
            logger.error("Scan not posted yet")
            return
        
        if self.get_status()["status"] not in ["running", "pending", "resuming"]:
            logger.error("Scan not running, pending or resuming")
            return

        x = json.loads(requests.post(f"{self.nessus_server}/scans/{self.id}/stop", headers=self.headers, verify=False).text)
        logger.info("Scan stopped: " + str(x["scan"]["id"]) + " (" + self.metadata["settings"]["name"] + ")")
        return x["scan"]["id"]
    
    def force_stop(self):
        if not self.id:
            logger.error("Scan not posted yet")
            return

        x = json.loads(requests.post(f"{self.nessus_server}/scans/{self.id}/force-stop", headers=self.headers, verify=False).text)
        logger.info("Scan force stopped: " + str(x["scan"]["id"]) + " (" + self.metadata["settings"]["name"] + ")")
        return x["scan"]["id"]

    def dump(self):
        return {
            "id":self.id,
            "nessus_server":self.nessus_server,
            "metadata":self.metadata,
        }

    def get_reports(self, path: str):
        if not self.id:
            logger.error("Scan not posted yet")
            return
        if self.get_status()["status"] not in ["completed", "canceled", "imported", "aborted"]:
            logger.error("Scan not finished yet")
            return

        for t in self.export_types:
            data = json.loads('{"format":"csv","reportContents":{"csvColumns":{"id":true,"cve":true,"cvss":true,"risk":true,"hostname":true,"protocol":true,"port":true,"plugin_name":true,"synopsis":true,"description":true,"solution":true,"see_also":true,"plugin_output":true,"stig_severity":true,"cvss3_base_score":true,"cvss_temporal_score":true,"cvss3_temporal_score":true,"vpr_score":true,"risk_factor":true,"references":true,"plugin_information":true,"exploitable_with":true}},"extraFilters":{"host_ids":[],"plugin_ids":[]}}')
            data["format"] = t

            if t in ["html", "pdf"]:
                data = json.loads('{"format":"", "chapters": "vuln_by_plugin"}')
                data["format"] = t

            res = json.loads(requests.post(f"{self.nessus_server}/scans/{self.id}/export", headers=self.headers, json = data, verify=False).text)
            if "token" in res:
                logger.debug("Export in progress: " + res["token"])
                status = json.loads(requests.get(f"{self.nessus_server}/tokens/{res['token']}/status", headers=self.headers, verify=False).text)
                while status["status"] != "ready":
                    if status["status"] == "error":
                        logger.error("Error exporting scan type " + t + ": " + status)
                        quit()
                    sleep(0.5)
                    logger.debug(status)
                    status = json.loads(requests.get(f"{self.nessus_server}/tokens/{res['token']}/status", headers=self.headers, verify=False).text)
                if t == "pdf":
                    t_headers = self.headers
                    t_headers["Accept-Encoding"] = "gzip, deflate"
                    t_headers["Connection"] = "keep-alive"
                    t_headers["Accept"] = "*/*"
                else: t_headers = self.headers

                report_url = f"{self.nessus_server}/tokens/{res['token']}/download"
                filename = ''.join(random.choice(string.ascii_letters) for i in range(6))
                report_path = f"{path}/{slugify(self.metadata['settings']['name'], lowercase=False)}_{filename}.{t}"

                r = requests.get(report_url, headers=t_headers, verify=False)
                if r.status_code == 200:
                    with open(report_path, "wb") as f:
                        f.write(r.content)
                        logger.debug("Report downloaded: " + report_path)
            else:
                logger.error("Error exporting scan: " + res["error"])
                return None
        
        logger.success("Reports exported to " + path)
        return path
