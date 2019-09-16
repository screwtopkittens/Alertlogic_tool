#!/usr/bin/env python3

# AL TOOL PROOF OF CONCEPT VERSION

# Tool to pull data from ALERT LOGIC
# Author Daniel Speight
# Network Defence
# DESCRIPTION: A very quick proof of concept app to perform a number of a alert logic tasks.
# Dependencies required pip install blessings ,pip install requests

import requests
import json
from datetime import datetime
from blessings import Terminal
import math
import sys


def cust():
    try:
        cust_json = open("rack_cust.json", "r")
        cust_json_str = cust_json.read()
        cust_dict = json.loads(cust_json_str)
    except IOError:
        headers = {'Accept': 'application/json'}
        url_cust = "https://"+KEY+":@api.alertlogic.net/api/customer/v1/962"
        al_result = requests.get(url=url_cust,  headers=headers)
        al_cust = json.loads(al_result.text)
        rack_cust = {}
        y = 0
        for x in al_cust['child_chain']:
            bob = x['customer_name']
            bob3 = bob.split("-", 1)[0]
            bob3 = bob3.split(" ", 1)[0]
            bob2 = x['customer_id']
            rack_cust.update({bob3: bob2})
        dump = json.dumps(rack_cust)
        f = open("rack_cust.json", "w")
        f.write(dump)
        f.close()
        cust_json = open("rack_cust.json", "r")
        cust_json_str = cust_json.read()
        cust_dict = json.loads(cust_json_str)

    customer = input("please enter a rackspace account number: ")
    al_customer = cust_dict.get(customer)

    if al_customer == None:
        al_customer = input('Rackspace account not found please enter Alert logic account number')

    return al_customer


def refresh_cust():
    headers = {'Accept': 'application/json'}
    URL_CUST = "https://"+KEY+":@api.alertlogic.net/api/customer/v1/962"
    al_result = requests.get(url=URL_CUST,  headers=headers)
    al_cust = json.loads(al_result.text)
    rack_cust = {}
    y = 0
    for x in al_cust['child_chain']:
        bob = x['customer_name']
        bob3 = bob.split("-", 1)[0]
        bob3 = bob3.split(" ", 1)[0]
        bob2 = x['customer_id']
        rack_cust.update({bob3: bob2})
    test = json.dumps(rack_cust)
    f = open("rack_cust.json", "w")
    f.write(test)
    f.close()


def convert_size(size_bytes):
   if size_bytes == 0:
       return "0B"
   size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
   i = int(math.floor(math.log(size_bytes, 1024)))
   p = math.pow(1024, i)
   s = round(size_bytes / p, 2)
   return "%s %s" % (s, size_name[i])


def main_report():
    customer = cust()
    URL_IDS = "https://"+KEY+":@publicapi.alertlogic.net/api/tm/v1/"+str(customer)+"/appliances/"
    URL_LOG = "https://"+KEY+":@publicapi.alertlogic.net/api/lm/v1/"+str(customer)+"/appliances/?type=syslog"
    URL_LOG_SOURCES = "https://"+KEY+":@publicapi.alertlogic.net/api/lm/v1/"+str(customer)+"/sources?type=syslog"
    URL_LOG_SOURCES_EVENT = "https://"+KEY+":@publicapi.alertlogic.net/api/lm/v1/"+str(customer)+"/sources?type=eventlog"
    URL_LOG_SOURCES_FLAT = "https://"+KEY+":@publicapi.alertlogic.net/api/lm/v1/"+str(customer)+"/sources?type=flatfile"
    headers = {'Accept': 'application/json'}
    IDS_result = requests.get(url=URL_IDS, headers=headers)
    LOG_result = requests.get(url=URL_LOG, headers=headers)
    LOG_SOURCES_result =  requests.get(url=URL_LOG_SOURCES, headers=headers)
    LOG_SOURCES_EVENT_result = requests.get(url=URL_LOG_SOURCES_EVENT, headers=headers)
    LOG_SOURCES_FLAT_result = requests.get(url=URL_LOG_SOURCES_FLAT, headers=headers)
    IDS_output = json.loads(IDS_result.text)
    LOG_output = json.loads(LOG_result.text)
    LOG_SOURCES_output = json.loads(LOG_SOURCES_result.text)
    LOG_SOURCES_EVENT_output = json.loads(LOG_SOURCES_EVENT_result.text)
    LOG_SOURCES_FLAT_output = json.loads(LOG_SOURCES_FLAT_result.text)

    # Syslog info
    sys_new = 0
    sys_ok = 0
    sys_warning = 0
    sys_error = 0
    sys_offline = 0

    # eventlog info
    event_new = 0
    event_ok = 0
    event_warning = 0
    event_error = 0
    event_offline = 0

    # flatfile info
    flat_new = 0
    flat_ok = 0
    flat_warning = 0
    flat_error = 0
    flat_offline = 0

    for x in IDS_output['appliances']:
        ts = int(x['appliance']['status']['timestamp'])
        x['appliance']['status']['timestamp'] = (datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'))
        last_month = int(x['appliance']['stats']['last_month_tx_bytes'] + x['appliance']['stats']['last_month_rx_bytes'])
        x['appliance']['stats']['last_month_rx_bytes'] = convert_size(last_month)
        last_day = int(x['appliance']['stats']['last_day_tx_bytes'] + x['appliance']['stats']['last_day_rx_bytes'])
        x['appliance']['stats']['last_day_rx_bytes'] = convert_size(last_day)
        last_hour = int(x['appliance']['stats']['last_hour_tx_bytes'] + x['appliance']['stats']['last_hour_rx_bytes'])
        x['appliance']['stats']['last_hour_rx_bytes'] = convert_size(last_hour)

    for x in LOG_output['appliances']:
        ts = int(x['syslog']['status']['timestamp'])
        x['syslog']['status']['timestamp'] = (datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'))

    for x in LOG_SOURCES_output['sources']:
        if x['syslog']['status']['status'] == 'new':
            sys_new += 1
        if x['syslog']['status']['status'] == 'ok':
            sys_ok += 1
        if x['syslog']['status']['status'] == 'warning':
            sys_warning += 1
        if x['syslog']['status']['status'] == 'error':
            sys_error += 1
        if x['syslog']['status']['status'] == 'offline':
            sys_offline += 1

    for x in LOG_SOURCES_EVENT_output['sources']:
        if x['eventlog']['status']['status'] == 'new':
            event_new += 1
        if x['eventlog']['status']['status'] == 'ok':
            event_ok += 1
        if x['eventlog']['status']['status'] == 'warning':
            event_warning += 1
        if x['eventlog']['status']['status'] == 'error':
            event_error += 1
        if x['eventlog']['status']['status'] == 'offline':
            event_offline += 1

    for x in LOG_SOURCES_FLAT_output['sources']:
        if x['flatfile']['status']['status'] == 'new':
            flat_new += 1
        if x['flatfile']['status']['status'] == 'ok':
            flat_ok += 1
        if x['flatfile']['status']['status'] == 'warning':
            flat_warning += 1
        if x['flatfile']['status']['status'] == 'error':
            flat_error += 1
        if x['flatfile']['status']['status'] == 'offline':
            flat_offline += 1

    total_new = sys_new + event_new + flat_new
    total_ok = sys_ok + event_ok + flat_ok
    total_warning = sys_warning + event_warning + flat_warning
    total_error = sys_error + event_error + flat_error
    total_offline = sys_offline + event_offline + flat_offline

    # IDs Report
    print("===================================================")
    print(t.bold_underline('IDS Report'))
    for x in IDS_output['appliances']:
        print("Device", x['appliance']['name'])
        print("current Status", x['appliance']['status']['status'])
        print("Device up since", x['appliance']['status']['timestamp'])
        print("Usage last month", x['appliance']['stats']['last_month_rx_bytes'])
        print("Usage last day", x['appliance']['stats']['last_day_rx_bytes'])
        print("Usage last hour", x['appliance']['stats']['last_hour_rx_bytes'])
        print()

    # Log Report
    print("===================================================")
    print(t.bold_underline('Log Collectors Report'))
    for x in LOG_output['appliances']:
        print("Device", x['syslog']['name'])
        print("current Status", x['syslog']['status']['status'])
        print("Device up since", x['syslog']['status']['timestamp'])
        print()

    print("===================================================")
    print(t.bold_underline('Log source breakdown'))
    print()
    print(t.bold('syslog sources (Linux/network devices)'))
    print("new", sys_new)
    print(t.green('OK'), sys_ok)
    print(t.yellow('warning'), sys_warning)
    print(t.red('error'), sys_error)
    print(t.red('offline'), sys_offline)
    print()
    print(t.bold('Event log sources(Windows devices)'))
    print("new", event_new)
    print(t.green('OK'), event_ok)
    print(t.yellow('warning'), event_warning)
    print(t.red('error'), event_error)
    print(t.red('offline'), event_offline)
    print()
    print(t.bold('flat file sources'))
    print("new", flat_new)
    print(t.green('OK'), flat_ok)
    print(t.yellow('warning'), flat_warning)
    print(t.red('error'), flat_error)
    print(t.red('offline'), flat_offline)
    print()
    print(t.bold('Total Sources'))
    print("new", total_new)
    print(t.green('OK'), total_ok)
    print(t.yellow('warning'), total_warning)
    print(t.red('error'), total_error)
    print(t.red('offline'), total_offline)
    print()
    post_task()


def check_source(cust_source):
    customer_al = cust_source
    url_log_sources = "https://"+KEY+":@publicapi.alertlogic.net/api/lm/v1/"+str(customer_al)+"/sources"
    headers = {'Accept': 'application/json'}
    answer = "y"
    while answer == "y":
        params = dict(
            search=input("please enter search criteria: ")
             )
        log_sources_result = requests.get(url=url_log_sources, headers=headers, params=params)
        log_sources_output = json.loads(log_sources_result.text)
        try:
            for x in log_sources_output['sources']:
                ts_updated = int(x['eventlog']['status']['updated'])
                ts_created = int(x['eventlog']['created']['at'])
                x['eventlog']['status']['updated'] = (datetime.utcfromtimestamp(ts_updated).strftime('%Y-%m-%d %H:%M:%S'))
                x['eventlog']['created']['at'] = (datetime.utcfromtimestamp(ts_created).strftime('%Y-%m-%d %H:%M:%S'))

                header = 'Device {}, status: {}, last status change: {}'.format(
                         x['eventlog']['name'],
                         x['eventlog']['status']['status'],
                         x['eventlog']['status']['updated'],
                         )
                print(t.bold_underline(header))
                print()
                print(t.bold('statistics'))
                print(json.dumps(x['eventlog']['stats'], indent=5))
                print()
                print(t.bold('Details'))
                print("Agent type:", x['eventlog']['method'])
                print("Local IPv4 Addresses:", x['eventlog']['metadata']['local_ipv4'])
                print("OS Details:", x['eventlog']['metadata']['os_details'])
                print("processors:", x['eventlog']['metadata']['num_logical_processors'])
                print("Total Ram in MB:", x['eventlog']['metadata']['total_mem_mb'])
                print()
        except:
            print("not found")

        try:
            for x in log_sources_output['sources']:
                ts_updated = int( x['syslog']['status']['updated'])
                ts_created = int( x['syslog']['created']['at'])
                x['syslog']['status']['updated'] = (datetime.utcfromtimestamp(ts_updated).strftime('%Y-%m-%d %H:%M:%S'))
                x['syslog']['created']['at'] = (datetime.utcfromtimestamp(ts_created).strftime('%Y-%m-%d %H:%M:%S'))

                header = 'Device {}, status: {}, last status change: {}'.format(
                         x['syslog']['name'],
                         x['syslog']['status']['status'],
                         x['syslog']['status']['updated'],
                         )
                print(t.bold_underline(header))
                print()
                print(t.bold('statistics'))
                print(json.dumps(x['syslog']['stats'], indent=5))
                print()
                print(t.bold('Device Details'))
                print("Agent type:", x['syslog']['method'])
                print("Local IPv4 Addresses:", x['syslog']['metadata']['local_ipv4'])
                print("OS Details:", x['syslog']['metadata']['os_details'])
                print()
        except:
            print("not found")

        print("check another log source?")
        answer = input("Enter y for yes any other key for no: ")


def set_int_key():
    in_tkey = open("INTkey.txt", "w+")
    new_int_key = input("please insert your auth token....... nscli tokens -i ")
    in_tkey.write(new_int_key)
    in_tkey.close()


def sources_report():
    cust_sources = cust()
    url_log_sources = "https://" + KEY + ":@publicapi.alertlogic.net/api/lm/v1/" + str(cust_sources) + "/sources?type=syslog"
    url_log_sources_event = "https://" + KEY + ":@publicapi.alertlogic.net/api/lm/v1/" + str(cust_sources) + "/sources?type=eventlog"
    url_log_sources_flat = "https://" + KEY + ":@publicapi.alertlogic.net/api/lm/v1/" + str(cust_sources) + "/sources?type=flatfile"
    headers = {'Accept': 'application/json'}
    log_sources_result = requests.get(url=url_log_sources, headers=headers)
    log_sources_event_result = requests.get(url=url_log_sources_event, headers=headers)
    log_sources_flat_result = requests.get(url=url_log_sources_flat, headers=headers)
    log_sources_output = json.loads(log_sources_result.text)
    log_sources_event_output = json.loads(log_sources_event_result.text)
    log_sources_flat_output = json.loads(log_sources_flat_result.text)

    print(t.bold_underline('syslog sources (Linux/network devices'))
    print(t.bold_green('Devices in Up statuses'))
    for x in log_sources_output['sources']:
        ts = int(x['syslog']['status']['timestamp'])
        x['syslog']['status']['timestamp'] = (datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'))
        if x['syslog']['status']['status'] == 'ok' and x['syslog']['stats']['last_day_events'] > 0:
            ok_syslog = '{}, OK timestamp: {}, last day events: {}'.format(
                x['syslog']['name'],
                x['syslog']['status']['timestamp'],
                x['syslog']['stats']['last_day_events']
            )
            print (t.bold_green(ok_syslog))
        elif x['syslog']['status']['status'] == 'warning' and x['syslog']['stats']['last_day_events'] > 0:
            warning_syslog = '{}, warning timestamp: {}, last day events: {}'.format(
                x['syslog']['name'],
                x['syslog']['status']['timestamp'],
                x['syslog']['stats']['last_day_events']
            )
            print(t.bold_yellow(warning_syslog))
        elif x['syslog']['status']['status'] == 'new' and x['syslog']['stats']['last_day_events'] > 0:
            new_syslog = '{}, new timestamp: {}, last day events: {}'.format(
                x['syslog']['name'],
                x['syslog']['status']['timestamp'],
                x['syslog']['stats']['last_day_events']
            )
            print(t.bold_blue(new_syslog))
    print()
    print(t.bold_yellow('Devices with no log events in last day'))
    for x in log_sources_output['sources']:
        if x['syslog']['status']['status'] == 'ok' and x['syslog']['stats']['last_day_events'] == 0 or 'warning' and x['syslog']['stats']['last_day_events'] == 0 or 'new' and x['syslog']['stats']['last_day_events'] == 0:
            no_events_syslog = '{}, {} timestamp: {}, last day events: {}'.format(
                x['syslog']['name'],
                x['syslog']['status']['status'],
                x['syslog']['status']['timestamp'],
                x['syslog']['stats']['last_day_events']
            )
            print(t.bold_yellow(no_events_syslog))
    print()
    print(t.bold_red('Devices in down statuses'))
    for x in log_sources_output['sources']:
        if x['syslog']['status']['status'] == 'error':
            error_syslog = '{}, ERROR timestamp: {}, last day events: {}'.format(
                x['syslog']['name'],
                x['syslog']['status']['timestamp'],
                x['syslog']['stats']['last_day_events']
            )
            print(t.bold_red(error_syslog))
        elif x['syslog']['status']['status'] == 'offline':
            offline_syslog = '{}, OFFLINE timestamp: {}, last day events: {}'.format(
                x['syslog']['name'],
                x['syslog']['status']['timestamp'],
                x['syslog']['stats']['last_day_events']
            )
            print(t.bold_red(offline_syslog))
    print()
    print(t.bold_underline('Event log sources(Windows devices)'))
    print(t.bold_green('Devices in Up statuses'))
    for x in log_sources_event_output['sources']:
        ts = int(x['eventlog']['status']['timestamp'])
        x['eventlog']['status']['timestamp'] = (datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'))
        if x['eventlog']['status']['status'] == 'ok' and x['eventlog']['stats']['last_day_events'] > 0:
            ok_eventlog = '{}, OK timestamp: {}, last day events: {}'.format(
                x['eventlog']['name'],
                x['eventlog']['status']['timestamp'],
                x['eventlog']['stats']['last_day_events']
            )
            print(t.bold_green(ok_eventlog))
        elif x['eventlog']['status']['status'] == 'warning' and x['eventlog']['stats']['last_day_events'] > 0:
            warning_eventlog = '{}, warning timestamp: {}, last day events: {}'.format(
                x['eventlog']['name'],
                x['eventlog']['status']['timestamp'],
                x['eventlog']['stats']['last_day_events']
            )
            print(t.bold_yellow(warning_eventlog))
        elif x['eventlog']['status']['status'] == 'new' and x['eventlog']['stats']['last_day_events'] > 0:
            new_eventlog = '{}, new timestamp: {}, last day events: {}'.format(
                x['eventlog']['name'],
                x['eventlog']['status']['timestamp'],
                x['eventlog']['stats']['last_day_events']
            )
            print(t.bold_blue(new_eventlog))
    print()
    print(t.bold_yellow('Devices with no log events in last day'))
    for x in log_sources_event_output['sources']:
        if x['eventlog']['status']['status'] == 'ok' and x['eventlog']['stats']['last_day_events'] == 0 or 'warning' and x['eventlog']['stats']['last_day_events'] == 0 or 'new' and x['eventlog']['stats']['last_day_events'] == 0:
            no_events_eventlog = '{}, {} timestamp: {}, last day events: {}'.format(
                x['eventlog']['name'],
                x['eventlog']['status']['status'],
                x['eventlog']['status']['timestamp'],
                x['eventlog']['stats']['last_day_events']
            )
            print(t.bold_yellow(no_events_eventlog))
    print()
    print(t.bold_red('Devices in down statuses'))
    for x in log_sources_event_output['sources']:
        if x['eventlog']['status']['status'] == 'error':
            error_eventlog = '{}, ERROR timestamp: {}, last day events: {}'.format(
                x['eventlog']['name'],
                x['eventlog']['status']['timestamp'],
                x['eventlog']['stats']['last_day_events']
            )
            print (t.bold_red(error_eventlog))
        elif x['eventlog']['status']['status'] == 'offline':
            offline_eventlog = '{}, OFFLINE timestamp: {}, last day events: {}'.format(
                x['eventlog']['name'],
                x['eventlog']['status']['timestamp'],
                x['eventlog']['stats']['last_day_events']
            )
            print(t.bold_red(offline_eventlog))
    print()
    print(t.bold_underline('flat file sources'))
    for x in log_sources_flat_output['sources']:
        ts = int( x['flatfile']['status']['timestamp'])
        x['flatfile']['status']['timestamp'] = (datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'))
        flatfile_sources = '{}, {} timestamp: {}, last day events: {}'.format(
            x['flatfile']['name'],
            x['flatfile']['status']['status'],
            x['flatfile']['status']['timestamp'],
            x['flatfile']['stats']['last_day_events']
        )
        print(t.bold(flatfile_sources))
    post_task()


def ids_report():
    cust_ids = cust()
    url_ids = "https://" + KEY + ":@publicapi.alertlogic.net/api/tm/v1/" + str(cust_ids) + "/appliances/"
    headers = {'Accept': 'application/json'}
    ids_result = requests.get(url=url_ids, headers=headers)
    ids_output = json.loads(ids_result.text)
    for x in ids_output['appliances']:
        ts = int( x['appliance']['status']['timestamp'])
        x['appliance']['status']['timestamp'] = (datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'))
        last_month = int(
            x['appliance']['stats']['last_month_tx_bytes']
            + x['appliance']['stats']['last_month_rx_bytes']
            )
        x['appliance']['stats']['last_month_rx_bytes'] = convert_size(last_month)
        last_day = int(
            x['appliance']['stats']['last_day_tx_bytes']
            + x['appliance']['stats']['last_day_rx_bytes']
            )
        x['appliance']['stats']['last_day_rx_bytes'] = convert_size(last_day)
        last_hour = int(
            x['appliance']['stats']['last_hour_tx_bytes']
            + x['appliance']['stats']['last_hour_rx_bytes']
              )
        x['appliance']['stats']['last_hour_rx_bytes'] = convert_size(last_hour)
    print(json.dumps(ids_output, indent=5))
    post_task()


def ssl_audit():
    cust_ssl_audit = cust()
    url_ssl = "https://" + KEY + ":@publicapi.alertlogic.net/api/tm/v1/" + str(cust_ssl_audit) + "/keypairs"
    headers = {'Accept': 'application/json'}
    ssl_result = requests.get(url=url_ssl, headers=headers)
    ssl_output = json.loads(ssl_result.text)
    for x in ssl_output['keypairs']:
        ts = int(x['keypair']['created']['at'])
        x['keypair']['created']['at'] = (datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'))
        certificate_file = '{}, uploaded at: {} '.format(
            x['keypair']['name'],
            x['keypair']['created']['at']
        )
        print(certificate_file)
    print("total certificates", ssl_output['total_count'])
    post_task()


def ssl_audit_full():
    params = dict(
        coreid=input("Please enter a account you wish to search for to test all certificates "),
        corequerytype="account",
        coretoken=input("Please enter a valid coretoken and press enter: ")
    )
    headers2 = {'Content-Type': 'application/json', 'X-Auth-Token': INTKEY}
    url = "https://api.ssltool.rackspace.com/coreiplist"
    resp = requests.post(url, headers=headers2, json=params)
    output = json.loads(resp.text)
    print(json.dumps(output, indent=5))


def ssl_audit_adv():
    cust_ssl_audit_adv = cust()
    params_ssl = dict(
        search=input("Please enter a domain you wish to search for on the IDS if you wish to test all certificates "
                     "just press enter: ")
    )
    url_ssl = "https://" + KEY + ":@publicapi.alertlogic.net/api/tm/v1/" + str(cust_ssl_audit_adv) + "/keypairs"
    headers = {'Accept': 'application/json'}
    if params_ssl['search'] == "":
        ssl_result = requests.get(url=url_ssl, headers=headers)
    else:
        ssl_result = requests.get(url=url_ssl, headers=headers, params=params_ssl)
    ssl_output = json.loads(ssl_result.text)
    headers2 = {'Content-Type': 'application/json', 'X-Auth-Token': INTKEY}
    url = "https://api.ssltool.rackspace.com/viewcert"
    url_cipher_test = "https://api.ssltool.rackspace.com/remotecert"

    for x in ssl_output['keypairs']:
        params = dict(
            certificate=x['keypair']['certificate']
        )
        ts = int(x['keypair']['created']['at'])
        x['keypair']['created']['at'] = (datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'))
        resp = requests.post(url, headers=headers2, json=params)
        cert_output = json.loads(resp.text)
        print("=======================================================================================================")
        certificate_file = 'Alert logic filename: {}, uploaded at: {} '.format(
            x['keypair']['name'],
            x['keypair']['created']['at']
        )
        print(t.bold(certificate_file))
        print()
        print(t.bold_underline('Certificate Details'))
        print(t.bold('Common Name: '), cert_output['0']['data']['cn'])
        try:
            print(t.bold('Alternative names: '), cert_output['0']['data']['alt'])
        except:
            print("No alt names")
        print(t.bold('serial: '), cert_output['0']['data']['serial'])
        print(t.bold('Valid From: '), cert_output['0']['data']['begin'])
        print(t.bold('Valid To: '), cert_output['0']['data']['end'])
        print()

        site = cert_output['0']['data']['cn']
        site = site.replace('*','www')
        cipher_test_params = dict(
            host=site,
            port="443")
        try:
            cipher_test = requests.post(url_cipher_test, headers=headers2, json=cipher_test_params )
            cipher_test_output = json.loads(cipher_test.text)
            print(t.bold_underline('Connection to Site'))
            print(t.bold('Site response over port 443: '), cipher_test.status_code)
            ip_test = ip_tool(cert_output['0']['data']['cn'])
            print(ip_test)
            print()
            print(t.bold_underline('Live site certificate details'))
            print(t.bold('Common Name: '), cipher_test_output['0']['data']['cn'])
            try:
                print(t.bold('Alternative names: '), cipher_test_output['0']['data']['alt'])
            except:
                print("No alt names")
            print(t.bold('serial: '), cipher_test_output['0']['data']['serial'])
            print(t.bold('Valid From: '), cipher_test_output['0']['data']['begin'])
            print(t.bold('Valid To: '), cipher_test_output['0']['data']['end'])
            print(t.bold('Preferred Cipher: '), cipher_test_output['chain']['info']['preferredcipher'])
            print(t.bold('Preferred SSL/TLS version: '), cipher_test_output['chain']['info']['preferredsslver'])
        except:
            print("unable to obtain site info")
            print(cipher_test.headers)
            continue
        print()
        print(t.bold_underline('Audit Results'))
        try:
            if cipher_test_output['0']['data']['serial'] == cert_output['0']['data']['serial']:
                print(t.bold_green('certificates Match'))
            else:
                print(t.bold_red('certificates do not match'))
        except:
            print("n/a")
            continue
        try:
            if "Rackspace" in ip_test:
                print(t.bold_green('Site resolves to Rackspace'))
            else:
                print(t.bold_red('Site resolves elsewhere'))
        except:
            print("n/a")
            continue
        try:
            if "DH" in cipher_test_output['chain']['info']['preferredcipher']:
                print(t.bold_red('Diffie Hellman Ciphers in use'))
            else:
                print(t.bold_green('Non Diffie Hellman cipher'))
        except:
            print("n/a")
            continue
        print("=======================================================================================================")

    print("total certificates", ssl_output['total_count'])
    print()
    post_task()


def cve_tool():

    cve_input = input("please enter the CVE Number to scan")
    url = "https://cve.circl.lu/api/cve/" + cve_input
    headers = {'Accept': 'application/json'}

    result = requests.get(url=url, headers=headers)
    output = json.loads(result.text)
    print(t.bold_underline('summary'))
    print(output['summary'])
    print()
    print(t.bold('Vulnerable Systems'))
    print(json.dumps(output['vulnerable_configuration_cpe_2_2'], indent=5))
    print()
    print(t.bold('Access Impact'))
    try:
        print(json.dumps(output['access'], indent=5))
    except:
        print("No Details")
    print()
    print(t.bold('C.I.A Impact'))
    try:
        print(json.dumps(output['impact'], indent=5))
    except:
        print("No Details")
    print()
    print(t.bold('References'))
    try:
        print(json.dumps(output['references'], indent=5))
    except:
        print("No Details")

    post_task()


def site_checker(url, identity_token):
    headers2 = {'Content-Type': 'application/json', 'X-Auth-Token': identity_token}
    url_cipher_test = "https://api.ssltool.rackspace.com/remotecert"
    cipher_test_params = dict(
        host=url,
        port="443")
    try:
        cipher_test = requests.post(url_cipher_test, headers=headers2, json=cipher_test_params )
        cipher_test_output = json.loads(cipher_test.text)
        print(t.bold_underline('Connection to Site'))
        print(t.bold('Site response over port 443: '), cipher_test.status_code)
        ip_test = ip_tool(cipher_test_output['0']['data']['cn'])
        print(ip_test)
        print()
        print(t.bold_underline('Live site certificate details'))
        print(t.bold('Common Name: '), cipher_test_output['0']['data']['cn'])
        try:
            print(t.bold('Alternative names: '), cipher_test_output['0']['data']['alt'])
        except:
            print("No alt names")
        print(t.bold('serial: '), cipher_test_output['0']['data']['serial'])
        print(t.bold('Valid From: '), cipher_test_output['0']['data']['begin'])
        print(t.bold('Valid To: '), cipher_test_output['0']['data']['end'])
        print(t.bold('Preferred Cipher: '), cipher_test_output['chain']['info']['preferredcipher'])
        print(t.bold('Preferred SSL/TLS version: '), cipher_test_output['chain']['info']['preferredsslver'])
    except:
        print("unable to connect to site")
        print(cipher_test.headers)
    print()
    print(t.bold_underline('Site Results'))
    try:
        if "Rackspace" in ip_test:
            print(t.bold_green('Site resolves to Rackspace'))
        else:
            print(t.bold_red('Site resolves elsewhere'))
        if "DH" in cipher_test_output['chain']['info']['preferredcipher']:
            print(t.bold_red('Diffie Hellman Ciphers in use'))
        else:
            print(t.bold_green('Non Diffie Hellman cipher'))
    except:
        print("no site resolved")
    return


def ip_tool(ip):
    try:
        url = "http://ip-api.com/json/" + ip
        headers = {'Accept': 'application/json'}
        result = requests.get(url=url, headers=headers)
        output = json.loads(result.text)
        url_output = '{}, {} provider {}, Country {} organisation {}'.format(
                        ip,
                        output['query'],
                        output['as'],
                        output['country'],
                        output['org']
                        )
    except:
        print("error unable to resolve site")
        url_output = None
    return url_output


def post_task():
    print()
    print("press 1. Return to menu")
    print("press any other key to exit")
    choice = input("enter selection ")
    try:
        if choice == "1":
            main()
        elif choice == "2":
            sys.exit()
    except:
        t.bold_red('NOT a Valid input exiting application')
        sys.exit()


def site_audit():
    print(t.bold('Welcome to the site checker please select how to proceed'))
    print("1. Enter single site")
    print("2. Batch enter comma separated list")
    selection = input("enter selection: ")
    token = INTKEY

    if selection == "1":
        site_input = input("enter sites: ")
        site_checker(site_input, token)
    elif selection == "2":
        site_input = input("enter sites separated by comma and no spaces: ")
        site_list = site_input.split(",")
        y = 0
        for x in site_list:
            site = site_list[y]
            print(site)
            site_checker(site, token)
            y += 1


def main():
    print("   #                               #                                                                  ")
    print("  # #   #      ###### #####  ##### #        ####   ####  #  ####    #####  ####   ####  #       ####  ")
    print(" #   #  #      #      #    #   #   #       #    # #    # # #    #     #   #    # #    # #      #      ")
    print("#     # #      #####  #    #   #   #       #    # #      # #          #   #    # #    # #       ####  ")
    print("####### #      #      #####    #   #       #    # #  ### # #          #   #    # #    # #           # ")
    print("#     # #      #      #   #    #   #       #    # #    # # #    #     #   #    # #    # #      #    # ")
    print("#     # ###### ###### #    #   #   #######  ####   ####  #  ####      #    ####   ####  ######  ####  ")
    print(t.bold_red('Version 0.3a'))
    print(t.bold('FYI This is a poorly coded test python script as a proof of concept so not everything will work as '
                 'expected a nice efficient script and NSCLI integration will come later. '))
    print(t.bold('For any improvements or suggestions reach out to Daniel Speight in Network Defence'))
    print(t.bold_underline('REPORTS'))
    print(" 1. General overview report of IDS/Log")
    print(" 2. Sources report")
    print(" 3. SSL Audit IDS basic(list output of file name on ids , upload date)")
    print(" 4. SSL Audit Advanced(this will give a lot of information and provide ciphers in use, if site is live and "
          "if it matches content from IDS)")
    print(" 5. IDS Appliance Report(basic json dump so far with some conversion for time)")
    print(" 6. check log source")
    print(" 7. SSL Audit enviroment basic")
    print()
    print(t.bold_underline('Additional Tools'))
    print(" a. CVE information tool(basic build so far)")
    print(" b. IP/domain Location information tool(basic build so far )")
    print(" c. Site checker (tool to check site compatibility with the IDS/WebApp IDS)")
    print()
    print(t.bold_underline('DEBUG'))
    print(" x. Refresh rack customer DB")

    selection = input("please select the report you would like to run ")
    if selection == "1":
        main_report()
    elif selection == "2":
        sources_report()
    elif selection == "3":
        ssl_audit()
    elif selection == "4":
        ssl_audit_adv()
    elif selection == "5":
        ids_report()
    elif selection == "6":
        customer_bob = cust()
        check_source(customer_bob)
    elif selection =="7":
        ssl_audit_full()
    elif selection == "a":
        cve_tool()
    elif selection == "b":
        print(t.bold('Welcome to the IP/DNS Location Tool please select how to proceed'))
        print("1. Enter single ip/domain")
        print("2. Batch enter comma separated list")
        ip_option = input("enter selection: ")
        if ip_option == "1":
            ip_input = input("enter IP/Domain: ")
            print(ip_tool(ip_input))
        elif ip_option == "2":
            ip_input = input("enter IPs/Domains separated by comma and no spaces: ")
            ip_list = ip_input.split(",")
            y = 0
            for x in ip_list:
                ip = ip_list[y]
                print(ip_tool(ip))
                y += 1
    elif selection == "c":
        site_audit()
    elif selection == "x":
        refresh_cust()


# GLOBAL OBJECTS OH NO
t = Terminal()
try:
    APIkey = open("APIkey.txt", "r")
except IOError:
    APIkey = open("APIkey.txt", "w+")
    newkey = input("enter your alert logic API key and press enter to proceed ")
    APIkey.write(newkey)
    APIkey.close()
    APIkey = open("APIkey.txt", "r")

try:
    INT_key = open("INTkey.txt", "r")
except IOError:
    set_int_key()
    INT_key = open("INTkey.txt", "r")


INTKEY = INT_key.read(1000)
KEY = APIkey.read(100)

int_test_header = {'Content-Type': 'application/json', 'X-Auth-Token': INTKEY}
int_test_url = "https://api.ssltool.rackspace.com/changelog"
test_params = dict(
        )
test_resp = requests.post(int_test_url, headers=int_test_header, json=test_params)
print(test_resp.status_code)

if test_resp.status_code == 200:
    print("INT Key Valid")
elif test_resp.status_code != 200:
    set_int_key()
    INT_key = open("INTkey.txt", "r")
    INTKEY = INT_key.read(1000)

main()
post_task()




