#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
This is a sub-component of the nessusbeat service.

The purpose of this component is to handle the communications with the nessus vulnerability-scanner.

'''

import os
from pathlib import Path
import yaml
import requests
import json
import time
import urllib3
from xml.etree import ElementTree as ET
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class nessuscommunication(object):

  def get_nessus_folders(self, headers, nessus_url):
    print("Nessusbeat: Fetching nessus folders")
    folders_url = "{}/folders".format(nessus_url)
    nessusfolders=requests.request('GET', folders_url, headers=headers, verify=False)
    if nessusfolders.status_code == 200:
      print("Nessusbeat: Nessus folders succesfully fetched")
      return nessusfolders.json()
    else:
      Print("Nessusbeat: Could not fetch nessus folders")
      return False


  def get_nessus_scans(self, headers, folder_id, nessus_url):
    print("Nessusbeat: Fetching list of nessus scans in folder with id={}".format(str(folder_id)))
    scans_url = "{}/scans?folder_id={}".format(nessus_url, str(folder_id))
    nessusfolder=requests.request('GET', scans_url, headers=headers, verify=False)
    if nessusfolder.status_code == 200:
      print("Nessusbeat: List of nessus-scans in folder with id={} succesfully fetched".format(str(folder_id)))
      return nessusfolder.json()
    else:
      print("Nessusbeat: Unable to fetch list of nessus-scans in folder with id={}".format(str(folder_id)))
      return False

  def get_nessus_scan(self, headers, scan_id, nessus_url):
    print("Nessusbeat: Fetching nessus scan with id={}".format(str(scan_id)))
    scan_url= "{}/scans/{}".format(nessus_url, scan_id)
    nessusscan=requests.request('GET', scan_url, headers=headers, verify=False)
    if nessusscan.status_code == 200:
      print("Nessusbeat: Succesfully fetched nessus-scan with id={}".format(str(scan_id)))
      return nessusscan.json()
    else:
      print("Nessusbeat: Unable to fetch nessus-scan with id={}".format(str(scan_id)))
      return False


  def get_nessus_ticket(self, headers, scan_id, nessus_url, history_id=''):
    ticket_url=""
    if history_id:
      print("Nessusbeat: Fetching ticket for nessus scan with scan-id={} and history-id={}".format(str(scan_id), str(history_id)))
      ticket_url = "{}/scans/{}/export?history_id={}".format(nessus_url, scan_id, history_id)
    else:
      print("Nessusbeat: Fetching ticket for nessus scan with scan-id={} and no previous historic scans".format(str(scan_id)))
      ticket_url = "{}/scans/{}/export".format(nessus_url, scan_id)
    outputformat='{"format":"nessus"}'
    nessusticket=requests.request('POST', ticket_url, data=outputformat, headers=headers, verify=False)
    if nessusticket.status_code == 200:
      print("Nessusbeat: succesfully fetched ticket for nessus scan with scan-id={}".format(str(scan_id)))
      jsondata=nessusticket.json()
      if 'token' in jsondata:
        print("Nessusbeat: returning download-token for nessus-scan with scan-id={}".format(str(scan_id)))
        return jsondata['token']
      else:
        print("Nessusbeat: Ticket for nessus-scan with scan-id={}, did not contain a download-token".format(str(scan_id)))
        return False
    else:
      print("Nessusbeat: Unable to fetch ticket for nessus scan with scan-id={}".format(str(scan_id)))
      return False


  def get_nessus_download_status(self, headers, nessus_url, token):
    print("Nessusbeat: Fetching download status")
    status_url = "{}/tokens/{}/status".format(nessus_url, token)
    nessusstatus=requests.request('GET', status_url, headers=headers, verify=False)
    if nessusstatus.status_code == 200:
      jsondata=nessusstatus.json()
      if 'status' in jsondata:
        if jsondata['status'] == 'ready':
          print("Nessusbeat: Download status = Ready")
          return True
        else:
          print("Nessusbeat: Download status = Not Ready")
          return False
      else:
        print("Nessusbeat: Download status not found in response")
        return False
    else:
      print("Nessusbeat: Unable to fetch download status")
      return False


  def get_nessus_file(self, headers, nessus_url, token):
    print("Nessusbeat: Downloading nessus_scan")
    download_url = "{}/tokens/{}/download".format(nessus_url, token)
    nessusdownload=requests.request('GET', download_url, headers=headers, verify=False)
    if nessusdownload.status_code == 200:
      print("Nessusbeat: Succesfully downloaded nessus scan")
      return ET.fromstring(nessusdownload.content)
    else:
      print("Nessusbeat: Unable to download nessus scan")
      return False

    
