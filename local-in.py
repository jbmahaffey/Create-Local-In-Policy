#!/usr/bin/env python3

import csv
import os
import sys
import ssl
import requests
import logging

ssl._create_default_https_context = ssl._create_unverified_context
requests.packages.urllib3.disable_warnings() 

def main():
    fortigate = input(str('Please enter IP address of FortiGate: '))
    print('If you use zones you must specify the zone name for external access for the next value.')
    extint = input(str('Please input external port name or zone name(ie. port1 or WAN_zone): '))
    password = input(str('Please input API key: '))
    
    adminport = ports(fortigate, password)

    devices = []
    with open(os.path.join(sys.path[0],'mgmt-ip.csv'), 'r') as vars_:
        for line in csv.DictReader(vars_):
            devices.append(line)
    mgip = {'all': devices}

    # Add address objects based on csv file
    try:
        address_url = 'https://{}/api/v2/cmdb/firewall/address'.format(fortigate)
        headers = {
            'Authorization': 'Bearer' + password, 
            'content-type': 'application/json'
            }

        for addr in mgip['all']:
            data = {
                'name': 'mgmt-ip-{}'.format(addr['mgmt-ip']),
                'type': 'ipmask',
                'subnet': addr['mgmt-ip'],
                'allow-routing': 'enable'
            }
            addresses = requests.post(address_url, headers=headers, json=data, verify=False)
            if addresses.status_code == 200:
                logging.info('Address {} added'.format(data['name']))
            else:
                logging.error('Unable to add address {}'.format(data['name']))
        
    except:
        logging.error('Unable to connect to Firewall')

    addgrp = []
    for addr in mgip['all']:
        addgrp.append({'name': 'mgmt-ip-{}'.format(addr['mgmt-ip'])})

    # create address group based on address objects in csv
    try:
        address_url = 'https://{}/api/v2/cmdb/firewall/addrgrp'.format(fortigate)
        headers = {
            'Authorization': 'Bearer' + password, 
            'content-type': 'application/json'
            }
        
        data = {
            'name': 'mgmt-ip-group',
            'type': 'default',
            'member': addgrp,
            'allow-routing': 'enable'
        }

        addg = requests.post(address_url, headers=headers, json=data, verify=False)

        if addg.status_code == 200:
            logging.info('Address group mgmt-ip-group added')
        else:
            logging.error('Unable to add address group mgmt-ip-group')

    except:
        logging.error('Unable to connect to Firewall')

    # Create local-in policy to allow address group
    try:
        address_url = 'https://{}/api/v2/cmdb/firewall/local-in-policy'.format(fortigate)
        headers = {
            'Authorization': 'Bearer' + password, 
            'content-type': 'application/json'
            }
        
        data = {
            'policyid': 100,
            'intf': '%s' % extint,
            'srcaddr': [
                {'name': 'mgmt-ip-group'}
            ],
            'dstaddr': [
                {'name': 'all'}
            ],
            'action': 'accept',
            'service': [
                {'name': adminport[0]},
                {'name': adminport[1]}
            ],
            'schedule': 'always',
            'status': 'enable'
        }

        localallow = requests.post(address_url, headers=headers, json=data, verify=False)

        if localallow.status_code == 200:
            logging.info('local-in policy allowing traffic to address group created')
        else:
            logging.error('local-in policy could not be created')

    except:
        logging.error('Unable to connect to Firewall')

    # Create local-in policy to allow address group
    try:
        address_url = 'https://{}/api/v2/cmdb/firewall/local-in-policy'.format(fortigate)
        headers = {
            'Authorization': 'Bearer' + password, 
            'content-type': 'application/json'
            }
        
        data = {
            'policyid': 101,
            'intf': '%s' % extint,
            'srcaddr': [
                {'name': 'all'}
            ],
            'dstaddr': [
                {'name': 'all'}
            ],
            'action': 'deny',
            'service': [
                {'name': adminport[0]},
                {'name': adminport[1]}
            ],
            'schedule': 'always',
            'status': 'enable'
        }

        localdeny = requests.post(address_url, headers=headers, json=data, verify=False)

        if localdeny.status_code == 200:
            logging.info('local-in policy allowing traffic to address group created')
        else:
            logging.error('local-in policy could not be created')

    except:
        logging.error('Unable to connect to Firewall')

def ports(fortigate, password):
    try:
        address_url = 'https://{}/api/v2/cmdb/system/global'.format(fortigate)
        headers = {
            'Authorization': 'Bearer' + password, 
            'content-type': 'application/json'
            }

        admports = requests.get(address_url, headers=headers, verify=False)

        httpport = admports.json()['results']['admin-port']
        httpsport = admports.json()['results']['admin-sport']

        portlist = []
        if httpport == 80:
            portlist.append('HTTP')
        else:
            try:
                address_url = 'https://{}/api/v2/cmdb/firewall.service/custom'.format(fortigate)
                headers = {
                    'Authorization': 'Bearer' + password, 
                    'content-type': 'application/json'
                    }

                data = {
                    "name": "mgmt-http-port",
                    "category": "General",
                    "protocol": "TCP/UDP/SCTP",
                    "protocol-number": 6,
                    "tcp-portrange": "{}".format(httpport),
                    "comment": "",
                    "color": 0,
                    "visibility": "enable",
                }

                mgmthttp = requests.post(address_url, headers=headers, json=data, verify=False)  

                if mgmthttp.status_code == 200:
                    portlist.append('mgmt-http-port')
                else:
                    raise Exception('Failed to add custom service')
            
            except:
                logging.error('Failed to add custom service for HTTP port')

        if httpsport == 443:
            portlist.append('HTTPS')
        else:
            try:
                address_url = 'https://{}/api/v2/cmdb/firewall.service/custom'.format(fortigate)
                headers = {
                    'Authorization': 'Bearer' + password, 
                    'content-type': 'application/json'
                    }

                data = {
                    "name": "mgmt-https-port",
                    "category": "General",
                    "protocol": "TCP/UDP/SCTP",
                    "protocol-number": 6,
                    "tcp-portrange": "{}".format(httpsport),
                    "comment": "",
                    "color": 0,
                    "visibility": "enable",
                }

                mgmthttps = requests.post(address_url, headers=headers, json=data, verify=False)  
                
                if mgmthttps.status_code == 200:
                    portlist.append('mgmt-https-port')
                else:
                    raise Exception('Failed to add custom service')
            
            except:
                logging.error('Failed to add custom service for HTTPS port')

        return portlist

    except:
        logging.error('Unable to get admin ports.')

if __name__ == '__main__':
   main()