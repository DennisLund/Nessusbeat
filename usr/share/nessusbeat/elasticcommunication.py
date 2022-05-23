#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
This is a sub-component of the nessusbeat service.

The purpose of this component is to handle the communications with the elasticsearch cluster.

'''

import os
from pathlib import Path
import yaml
import requests
import json
import time
import urllib3
from elasticsearch import Elasticsearch
from elasticsearch.connection import create_ssl_context
from elasticsearch import exceptions
import ssl
from ssl import create_default_context
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class elasticcommunication(object):

  elastic_hosts = []
  elastic_port = ""
  elastic_user = ""
  elastic_password = ""
  elastic_ssl_enabled = ""
  elastic_cert_validation = ""
  elastic_cert_ca_path = ""
  elastic_auth_enabled = ""
  elastic_index_name = ""
  elastic_pipeline = ""
  elastic_mapping_path = ""

  debug_mode = False

  def __init__(self):
    print("Nessusbeat: config-initialization begun")
    yml_data = {}
    with open("/etc/nessusbeat/nessusbeat.yml", "r") as file:
      yml_data = yaml.safe_load(file)
    for key in yml_data['elasticsearch.settings']:
      if 'hosts' in key:
        self.elastic_hosts = key['hosts']
        print("Nessusbeat-elastic:: elasticsearch_hosts initialized")
      elif 'port' in key:
        self.elastic_port = key['port']
        print("Nessusbeat-elastic:: elasticsearch_port initialized")
      elif 'username' in key:
        self.elastic_user = key['username']
        print("Nessusbeat-elastic:: elasticsearch_username initialized")
      elif 'password' in key:
        self.elastic_password = key['password']
        print("Nessusbeat-elastic:: elasticsearch_password initialized")
      elif 'ssl_cert_validation' in key:
        self.elastic_cert_validation = key['ssl_cert_validation']
        print("Nessusbeat-elastic:: elasticsearch_cert_validation initialized")
      elif 'cert_ca_path' in key:
        self.elastic_cert_ca_path = key['cert_ca_path']
        print("Nessusbeat-elastic:: elasticsearch_cert_ca_validation initialized")
      elif 'auth_enabled' in key:
        self.elastic_auth_enabled = key['auth_enabled']
        print("Nessusbeat-elastic:: elasticsearch_auth_enabled initialized")
      elif 'ssl_enabled' in key:
        self.elastic_ssl_enabled = key['ssl_enabled']
        print("Nessusbeat-elastic:: elasticsearch_ssl_enabled initialized")
      elif 'index_name' in key:
        self.elastic_index_name = key['index_name']
        print("Nessusbeat-elastic:: elasticsearch_index_name initialized")
      elif 'ingest_pipeline' in key:
        self.elastic_pipeline = key['ingest_pipeline']
        print("Nessusbeat-elastic:: elasticsearch_ingest_pipeline initialized")
      elif 'mapping_path' in key:
        self.elastic_mapping_path = key['mapping_path']
        print("Nessusbeat-elastic:: elasticsearch_mapping_path initialized")
    for key in yml_data['service.settings']:
      if 'debug_mode' in key:
        self.debug_mode = key['debug_mode']
        print("Nessusbeat-elastic: debug_mode initialized")
    print("Nessusbeat: config initialization succesful")



  def establish_connection(self):
    try:
      if self.elastic_auth_enabled:
        if self.elastic_ssl_enabled:
          if self.elastic_cert_validation:
            context = create_ssl_context(cafile=self.elastic_cert_ca_path)
            client = Elasticsearch(self.elastic_hosts, port=self.elastic_port, http_auth=(self.elastic_user, self.elastic_password), scheme="https", ssl_context=context)
            if(self.debug_mode is True):
              print('Nessusbeat-elastic:: Connection to elastic established with auth, ssl, cert_validation')
            return client
          else:
            context = create_ssl_context(cafile=self.elastic_cert_ca_path)
            context.check_hostname=False
            context.verify_mode=ssl.CERT_NONE
            client = Elasticsearch(self.elastic_hosts, port=self.elastic_port, http_auth=(self.elastic_user, self.elastic_password), scheme="https", ssl_context=context)
            if(self.debug_mode is True):
              print('Nessusbeat-elastic:: Connection to elastic established with auth, ssl')
            return client
        else:
          client = Elasticsearch(self.elastic_hosts, port=self.elastic_port, http_auth=(self.elastic_user, self.elastic_password))
          if(self.debug_mode is True):
            print('Nessusbeat-elastic:: Connection to elastic established with auth')
          return client
      else:
        if self.elastic_ssl_enabled:
          if self.elastic_cert_validation:
            context = create_ssl_context(cafile=self.elastic_cert_ca_path)
            client = Elasticsearch(self.elastic_hosts, port=self.elastic_port, scheme="https", ssl_context=context)
            if(self.debug_mode is True):
              print('Nessusbeat-elastic:: Connection to elastic established with ssl, cert_validation')
            return client
          else:
            context = create_ssl_context(cafile=self.elastic_cert_ca_path)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            client = Elasticsearch(self.elastic_hosts, port=self.elastic_port, scheme="https", ssl_context=context)
            if(self.debug_mode is True):
              print('Nessusbeat-elastic:: Connection to elastic established with ssl')
            return client
        else:
          client=Elasticsearch(self.elastic_hosts, port=self.elastic_port)
          if(self.debug_mode is True):
            print('Nessusbeat-elastic:: Connection to unsecured elastic established')
          return client
    except Exception as err:
      print ("NessusBeat-elastic:: Elasticsearch client ERROR in establish_connection: ", err)


  def check_index_exists(self, elastic_client):
    try:
      if elastic_client.indices.exists(index=self.elastic_index_name):
        return True
      else:
        return False
    except Exception as err:
      print ("NessusBeat-elastic:: Elasticsearch client ERROR in check_index_exists: ", err)


  def create_index(self, elastic_client):
    try:
      elastic_client.indices.create(index=self.elastic_index_name)
    except Exception as err:
      print ("NessusBeat-elastic:: Elasticsearch client ERROR in create_index: ", err)


  def index_document(self, elastic_client, json_doc):
    try:
      res=elastic_client.index(index=self.elastic_index_name, body=json_doc)
    except Exception as err:
      print ("NessusBeat-elastic:: Elasticsearch client ERROR in index_document: ", err)


  def create_index_with_mapping(self, elastic_client):
    req_body = {}
    with open(self.elastic_mapping_path, "r") as mapping_file:
      req_body = json.load(mapping_file)
    try:
      response = elastic_client.indices.create(index=self.elastic_index_name, body=req_body)
      status = response["acknowledged"]
      if status:
        print("Nessusbeat-elastic:: elastic index {} created.".format(self.elastic_index_name))
      else:
        print("Nessusbeat-elastic:: failed to create elastic index {}.".format(self.elastic_index_name))
      return status
    except Exception as err:
      print ("NessusBeat-elastic:: Elasticsearch client ERROR in create_index_with_mapping: ", err)

  #EXPERIMENTAL. NOT TESTED! MIGHT NOT BE NEEDED!!!
  def close_con(self, elastic_client):
    elastic_client.transport.close()

