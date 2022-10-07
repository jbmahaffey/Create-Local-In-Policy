#!/usr/bin/env python3

import csv
import os
import sys
import ssl
import requests
import logging
import datetime
import time

ssl._create_default_https_context = ssl._create_unverified_context
requests.packages.urllib3.disable_warnings() 

def main():
    fortigate = input(str('Please enter IP address of FortiGate: '))
    print('If you use zones you must specify the zone name for external access for the next value.')
    extint = input(str('Please input external port name or zone name(ie. port1 or WAN_zone): '))
    password = input(str('Please input API key: '))
    
    devices = []
    with open(os.path.join(sys.path[0],'mgmt-ip.csv'), 'r') as vars_:
        for line in csv.DictReader(vars_):
            devices.append(line)
    mgip = {'all': devices}

    # Add address objects based on csv file
    try:
        address_url = 'https://%s/api/v2/cmdb/firewall/address' % fortigate
        headers = {
            'Authorization': 'Bearer' + password, 
            'content-type': 'application/json'
            }

        for addr in mgip['all']:
            data = {
                'name': 'mgmt-ip-%s' % addr['mgmt-ip'],
                'type': 'ipmask',
                'subnet': addr['mgmt-ip'],
                'allow-routing': 'enable'
            }
            addresses = requests.post(address_url, headers=headers, json=data, verify=False)
            if addresses.status_code == 200:
                logging.info('Address %s added' % data['name'])
            else:
                logging.error('Unable to add address %s' % data['name'])
        
    except:
        logging.error('Unable to connect to Firewall')

    addgrp = []
    for addr in mgip['all']:
        addgrp.append({'name': 'mgmt-ip-%s' % addr['mgmt-ip']})

    # create address group based on address objects in csv
    try:
        address_url = 'https://%s/api/v2/cmdb/firewall/addrgrp' % fortigate
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
        address_url = 'https://%s/api/v2/cmdb/firewall/local-in-policy' % fortigate
        headers = {
            'Authorization': 'Bearer' + password, 
            'content-type': 'application/json'
            }
        
        data = {
            'policyid': 100,
            'intf': '%s' % extint,
            'srcaddr': [
                {'name': 'all'}
            ],
            'dstaddr': [
                {'name': 'mgmt-ip-group'}
            ],
            'action': 'accept',
            'service': [
                {'name': 'HTTP'},
                {'name': 'HTTPS'}
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
        address_url = 'https://%s/api/v2/cmdb/firewall/local-in-policy' % fortigate
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
                {'name': 'HTTP'},
                {'name': 'HTTPS'}
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

if __name__ == '__main__':
   main()