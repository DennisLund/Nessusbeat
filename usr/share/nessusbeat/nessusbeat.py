#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
This script was written by Dennis Lund Christiansen as a way to collect scan results from the nessus vulnerability-scanner, and index them into elasticsearch.

The purpose is to create better visibility regarding vulnerability management, meaning that, once the scan-results are indexed in elasticsearch, it should be much easier to see the development over time, as well as create automated priority lists over vulnerable assets.

The code has been written as a python service for linux, but it should work on windows too (Perhaps with some small adjustments).
'''

from nessuscommunication import nessuscommunication
from elasticcommunication import elasticcommunication
import nessusparsing

import os
from pathlib import Path
import yaml
import requests
import json
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Config(object):
  nessus_url = ""
  nessus_access_key = ""
  nessus_secret_key = ""
  nessus_wanted_folders = []
  nessus_wanted_statuses = []
  nessus_already_indexed_file = ""

  service_run_frequency = 3600
  debug_mode = False

  def __init__(self):
    print("Nessusbeat: Config-initialization begun")
    yml_data = {}
    with open("/etc/nessusbeat/nessusbeat.yml", "r") as file:
      yml_data = yaml.safe_load(file)
    for key in yml_data['nessusbeat.settings']:
      if 'url' in key:
        self.nessus_url = key['url']
        print("Nessusbeat: Nessus_url initialized")
      elif 'access-key' in key:
        self.nessus_access_key = key['access-key']
        print("Nessusbeat: Nessus_access_key initialized")
      elif 'secret-key' in key:
        self.nessus_secret_key = key['secret-key']
        print("Nessusbeat: Nessus_secret_key initialized")
      elif 'folders' in key:
        self.nessus_wanted_folders = key['folders']
        print("Nessusbeat: Nessus_wanted_folders initialized")
      elif 'status' in key:
        self.nessus_wanted_statuses = key['status']
        print("Nessusbeat: Nessus_wanted_statuses initialized")
      elif 'nessus-already-indexed-file' in key:
        self.nessus_already_indexed_file = key['nessus-already-indexed-file']
        print("Nessusbeat: Nessus_already_indexed_file initialized")
    for key in yml_data['service.settings']:
      if 'run_frequency' in key:
        self.service_run_frequency = key['run_frequency']
        print("Nessusbeat: Service_run_frequency initialized")
      if 'debug_mode' in key:
        self.debug_mode = key['debug_mode']
        print("Nessusbeat: debug_mode initialized")
    print("Nessusbeat: config initialization succesful")



# Checks that the indexed_scans file and the parent folder exists. Otherwise they are created
def check_indexed_scans_exists():
  if(os.path.exists(config.nessus_already_indexed_file)):
    if(config.debug_mode is True):
      print("Nessusbeat: Nessus_already_indexed_file exists")
  else:
    pth = Path(config.nessus_already_indexed_file)
    if(os.path.isdir(pth.parent)):
      if(config.debug_mode is True):
        print("Nessusbeat: Nessus_already_indexed_file does not exist, but the path does")
        print("Nessusbeat: Attempting to create nessus_already_indexed_file")
      file=open(str(pth),"w+")
      file.close()
      if(config.debug_mode is True):
        print("Nessusbeat: Nessus_already_indexed_file was created")
    else:
      if(config.debug_mode is True):
        print("Nessusbeat: Nessus_already_indexed_file and parent folder does not exist")
        print("Nessusbeat: Attempting to create nessus_already_indexed_file parent folder")
      os.mkdir(str(pth.parent))
      if(config.debug_mode is True):
        print("Nessusbeat: Attempting to create nessus_already_indexed_file")
      file=open(str(pth),"w+")
      file.close()
      if(config.debug_mode is True):
        print("Nessusbeat: Nessus_already_indexed_file was created")


def check_scan_id(scan_id):
  if(config.debug_mode is True):
    print("Nessusbeat: Checking scan_id {} against already indexed scans".format(str(scan_id)))
  with open(config.nessus_already_indexed_file , "r") as nessus_already_indexed_scans:
    if(scan_id in nessus_already_indexed_scans.read()):
      if(config.debug_mode is True):
        print("Nessusbeat: Nessus Scan-id: {} is in nessus_already_indexed_scans file".format(scan_id))
      return True
    else:
      if(config.debug_mode is True):
        print("Nessusbeat: Nessus Scan-id: {} is not in nessus_already_indexed_scans file".format(scan_id))
      return False


def write_scan_id_to_file(scan_id):
  if(config.debug_mode is True):
    print("Nessusbeat: Writing scan-id {} in already indexed scans".format(str(scan_id)))
  with open(config.nessus_already_indexed_file , "a") as nessus_already_indexed_scans:
    nessus_already_indexed_scans.write(str(scan_id) + "\n")


def check_folder(foldername):
  if(config.debug_mode is True):
    print("Nessusbeat: Checking nessus folder: {} against folders in nessusbeat.yml".format(foldername))
  if foldername in config.nessus_wanted_folders:
    if(config.debug_mode is True):
      print("Nessusbeat: Nessus folder: {} is in nessusbeat.yml".format(foldername))
    return True
  else:
    if(config.debug_mode is True):
      print("Nessusbeat: Nessus folder: {} is not in nessusbeat.yml".format(foldername))
    return False


def check_status(status):
  if(config.debug_mode is True):
    print("Nessusbeat: Checking nessus scan-status '{}' against statuses in nessusbeat.yml".format(status))
  if status in config.nessus_wanted_statuses:
    if(config.debug_mode is True):
      print("Nessusbeat: Nessus scan-status '{}' is in nessusbeat.yml".format(status))
    return True
  else:
    if(config.debug_mode is True):
      print("Nessusbeat: Nessus scan-status '{}' is not in nessusbeat.yml".format(status))
    return False



if __name__== "__main__":
  print("Nessusbeat: Nessusbeat service started")
  config = Config()
  headers = {"Content-Type":"application/json","x-apikeys":"accessKey={};secretKey={}".format(config.nessus_access_key, config.nessus_secret_key)}
  check_indexed_scans_exists()

  while True:
    print("Nessusbeat: Run loop started")
    nessus_coms = nessuscommunication()
    elastic_coms = elasticcommunication()
    nessus_folders = nessus_coms.get_nessus_folders(headers, config.nessus_url)
    elastic_client = elastic_coms.establish_connection()
    elastic_index_check = elastic_coms.check_index_exists(elastic_client)
    if not elastic_index_check:
      elastic_coms.create_index_with_mapping(elastic_client)
    if nessus_folders["folders"] is not None:
      for folder in nessus_folders["folders"]:
        if check_folder(folder["name"]):
          nessus_scans = nessus_coms.get_nessus_scans(headers, folder["id"], config.nessus_url)
          if isinstance(nessus_scans, dict) and nessus_scans["scans"] is not None:
            for scan in nessus_scans["scans"]:
              scan_id = scan["id"]
              nessus_scan = nessus_coms.get_nessus_scan(headers, scan_id, config.nessus_url)
              scanHistory = nessus_scan["history"]
              if scanHistory:
                for item in scanHistory:
                  status = item["status"]
                  uuid = item["uuid"]
                  history_id = item["history_id"]
                  ts = item["creation_date"]
                  if check_status(status):
                    if not check_scan_id(uuid):
                      nessus_ticket = nessus_coms.get_nessus_ticket(headers, scan_id, config.nessus_url, history_id)
                      if nessus_ticket:
                        download_status = False
                        download_failed = False
                        i=0
                        retries=60
                        while not download_status or not download_failed:
                          download_status = nessus_coms.get_nessus_download_status(headers, config.nessus_url, nessus_ticket)
                          if download_status:
                            break
                          i+=1
                          time.sleep(5)
                          if i >= retries:
                            download_failed = True
                        if download_failed:
                          if(config.debug_mode is True):
                            print("Nessusbeat: Failed to download scan with uuid={} and history:id={} in folder={}".format(uuid, history_id, folder["name"]))
                          continue
                        if(config.debug_mode is True):
                          print("Nessusbeat: Collecting nessus scan result")
                        nessus_output = nessus_coms.get_nessus_file(headers, config.nessus_url, nessus_ticket)
                        if(config.debug_mode is True):
                          print("Nessusbeat: Parsing nessus scan result")
                        parsed_result = nessusparsing.xmlparse(nessus_output, folder["name"], status, uuid, history_id)
                        for result in parsed_result:
                          for listing in result:
                            if(config.debug_mode is True):
                              print("Nessusbeat: Sending listing from nessus scan result to elasticsearch")
                            res = elastic_coms.index_document(elastic_client, listing)
                        write_scan_id_to_file(uuid)
                      else:
                        if(config.debug_mode is True):
                          print("Nessusbeat: Did not receive a download_ticket for scan-item with uuid - {} - and history_id - {} - in folder - {}".format(uuid, history_id, folder["name"]))
                    else:
                      if(config.debug_mode is True):
                        print("Nessusbeat: The nessus scan-item with uuid - {} - and history_id - {} - in folder - {} - is already in in indexed-scans.txt file (Meaning that it should already be indexed)".format(uuid, history_id, folder["name"]))
                  else:
                    if(config.debug_mode is True):
                      print("Nessusbeat: The nessus scan-item with uuid - {} - and history_id - {} - in folder - {} - with status - {} - does not have a status that is part of the wanted statuses in nessusbeat.yml".format(uuid, history_id, folder["name"], status))
        else:
          if(config.debug_mode is True):
            print("Nessusbeat: The folder with name - {} - Is not one of the wanted folders in nessusbeat.yml".format(folder["name"]))

    print("Nessusbeat: The nessusbeat service is going to sleep for {} seconds".format(str(config.service_run_frequency)))
    time.sleep(int(config.service_run_frequency))
