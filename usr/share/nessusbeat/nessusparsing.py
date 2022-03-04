#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
This is a sub-component of the nessusbeat service.

The purpose of this component is to parse the results from the nessus vulnerability scanner in order to make it conform to Elastic Common Schema

'''

import re
import datetime
import json


def validate_ipv4(ipv4):
  ipv4_regex="^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
  if re.match(ipv4_regex, ipv4):
    return True
  else:
    return False


def string_sanitizer(dirtyString):
  if dirtyString:
    cleanString=dirtyString.replace("\n", " ")
    return cleanString


report_tag_names = '/etc/nessusbeat/nessus-elastic-parsing/nessus_report_tag_names.json'
reportitem_attribute_names = '/etc/nessusbeat/nessus-elastic-parsing/nessus_reportitem_attribute_names.json'
reportitem_names = '/etc/nessusbeat/nessus-elastic-parsing/nessus_reportitem_names.json'


def xmlparse(resxml, nessusfolder, status, uuid, history_id):
  report=resxml.find('Report')
  reportname=str(report.get('name'))
  hosts=report.findall('ReportHost')
  resultList=[]
  for host in hosts:
    scanList=[]
    hostproperties=host.find('HostProperties')
    tags=hostproperties.findall('tag')
    tagvalues={}
    for tag in tags:
      tagvalues[tag.get('name')]=tag.text.lower()
    repitems=host.findall('ReportItem')
    for repitem in repitems:
      jsonobj={}
      with open(report_tag_names, 'r') as json_tags:
        temp_tags = json.load(json_tags)
        for k, v in temp_tags.items():
          if k in tagvalues:
            tempvar = v['ecs_field']
            if v['datatype'] == 'ipv4':
              if validate_ipv4(tagvalues[k]):
                if isinstance(tempvar, str):
                  jsonobj[tempvar] = tagvalues[k]
                else:
                  for field in tempvar:
                    jsonobj[field] = tagvalues[k]
            elif v['datatype'] == 'string_array':
              if isinstance(tempvar, str):
                jsonobj[tempvar] = tagvalues[k]
              else:
                for field in tempvar:
                  jsonobj[field] = tagvalues[k]
            elif v['datatype'] == 'timestamp':
              timevar = datetime.datetime.strptime(tagvalues[k], "%c")
              jsonobj[tempvar] = timevar
            else:
              if isinstance(tempvar, str):
                jsonobj[tempvar] = tagvalues[k]
              else:
                for field in tempvar:
                  jsonobj[field] = tagvalues[k]
          elif k == "nessusfolder":
            tempvar = v['ecs_field']
            jsonobj[tempvar] = nessusfolder
          elif k == "reportname":
            tempvar = v['ecs_field']
            jsonobj[tempvar] = reportname
      with open(reportitem_attribute_names, 'r') as json_attributes:
        temp_attribs = json.load(json_attributes)
        for k, v in temp_attribs.items():
          if repitem.get(k):
            tempvar = v['ecs_field']
            if v['datatype'] == 'ipv4':
              if validate_ipv4(repitem.get(k)):
                if isinstance(tempvar, str):
                  jsonobj[tempvar] = repitem.get(k)
                else:
                  for field in tempvar:
                    jsonobj[field] = repitem.get(k)
            elif v['datatype'] == 'string_array':
              if isinstance(tempvar, str):
                jsonobj[tempvar] = repitem.get(k)
              else:
                for field in tempvar:
                  jsonobj[field] = repitem.get(k)
            else:
              if isinstance(tempvar, str):
                jsonobj[tempvar] = repitem.get(k)
              else:
                for field in tempvar:
                  jsonobj[field] = repitem.get(k)
      with open(reportitem_names, 'r') as json_items:
        temp_items = json.load(json_items)
        for k, v in temp_items.items():
          tempvar = v['ecs_field']
          tempElem = repitem.findall(k)
          if tempElem and not tempElem==None:
            if v['datatype'] == 'ipv4':
              if validate_ipv4(tempElem.text):
                if isinstance(tempvar, str):
                  tempList = []
                  for elem in tempElem:
                    tempList.append(string_sanitizer(elem.text))
                  if len(tempList) > 1:
                    jsonobj[tempvar] = tempList
                  else:
                    jsonobj[tempvar] = tempList[0]
                else:
                  tempList = []
                  for elem in tempElem:
                    tempList.append(string_sanitizer(elem.text))
                  for field in tempvar:
                    if len(tempList) > 1:
                      jsonobj[field] = tempList
                    else:
                      jsonobj[field] = tempList[0]
            elif v['datatype'] == 'string_array':
              if isinstance(tempvar, str):
                tempList = []
                for elem in tempElem:
                  tempList.append(string_sanitizer(elem.text))
                if len(tempList) > 1:
                  jsonobj[tempvar] = tempList
                else:
                  jsonobj[tempvar] = tempList[0]
              else:
                tempList = []
                for elem in tempElem:
                  tempList.append(string_sanitizer(elem.text))
                for field in tempvar:
                  if len(tempList) > 1:
                    jsonobj[field] = tempList
                  else:
                    jsonobj[field] = tempList[0]
            else:
              if isinstance(tempvar, str):
                tempList = []
                for elem in tempElem:
                  tempList.append(string_sanitizer(elem.text))
                if len(tempList) > 1:
                  jsonobj[tempvar] = tempList
                else:
                  jsonobj[tempvar] = tempList[0]
              else:
                tempList = []
                for elem in tempElem:
                  tempList.append(string_sanitizer(elem.text))
                for field in tempvar:
                  if len(tempList) > 1:
                    jsonobj[field] = tempList
                  else:
                    jsonobj[field] = tempList[0]
      #Create a Unique ID for each scan-item, in order to track vulnerabilities over time
      if 'netbios-name' in tagvalues and repitem.get('port') and repitem.get('pluginID'):
        jsonobj['nessus.vulnerability.uid']='{}-{}-{}'.format(tagvalues['netbios-name'], repitem.get('port'), repitem.get('pluginID'))
      elif 'host-fqdn' in tagvalues and repitem.get('port') and repitem.get('pluginID'):
        jsonobj['nessus.vulnerability.uid']='{}-{}-{}'.format(tagvalues['host-fqdn'], repitem.get('port'), repitem.get('pluginID'))
      elif validate_ipv4(host.get('name')) and repitem.get('port') and repitem.get('pluginID'):
        jsonobj['nessus.vulnerability.uid']='{}-{}-{}'.format(host.get('name'), repitem.get('port'), repitem.get('pluginID'))
      elif 'host-ip' in tagvalues and repitem.get('port') and repitem.get('pluginID'):
        if validate_ipv4(tagvalues['host-ip']):
          jsonobj['nessus.vulnerability.uid']='{}-{}-{}'.format(tagvalues['host-ip'], repitem.get('port'), repitem.get('pluginID'))
      scanList.append(jsonobj)
    resultList.append(scanList)
  return resultList

