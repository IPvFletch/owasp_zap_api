#!/usr/bin/env python
#
# References:
#   https://github.com/zaproxy/zaproxy/wiki/ApiGen_Index
#   https://github.com/zaproxy/zaproxy/wiki/FAQapikey
#   https://github.com/ICTU/zap-baseline/blob/master/zap-baseline-custom.py
#   https://github.com/zaproxy/community-scripts/blob/master/api/sdlc-integration/core/scan_module/scan.py
#
#

from zapv2 import ZAPv2

import json
import requests
import os
import sys
import time


# Variables
apikey = '1234567890'
api_target = 'https://API_HOSTNAME/'
admin_target = 'https://ADMIN_HOSTNAME/'
api_user = os.environ['API_USER']
api_pass = os.environ['API_PASS']
api_hostname = os.environ['API_HOSTNAME']
api_url = 'https://' + api_hostname
api_data = {"username": api_user, "password": api_pass}
cookies = ''
auth_token = ''
jsessionid = ''
awsalb = ''
paths = []


# Get API Session Tokens
try:
    authz_response = requests.post(api_url + '/v2/api/signin', data=api_data)
    authz_response_content = json.loads(authz_response.content)
    cookies = authz_response.cookies
    auth_token = authz_response_content['AUTH_TOKEN']
except Exception:
    print 'API Failure for ' + api_hostname
    exit(1)


# Configure ZAP
zap = ZAPv2(apikey=apikey)
print 'Version: ' + zap.core.version
ctx_list = zap.context.context_list
if 'auth' not in ctx_list:
    zap.context.new_context('auth')

zap.context.include_in_context('auth', '\Q' + api_target + '\E.*')
zap.context.include_in_context('auth', '\Q' + admin_target + '\E.*')
zap.context.exclude_from_context('auth', '\Q/v2/api/signin\E.*')
zap.context.exclude_from_context('auth', '\Q/v2/api/signout\E.*')
zap.context.set_context_in_scope('auth', True)
zap.httpsessions.create_empty_session(api_target, 'auth')
zap.httpsessions.set_active_session(api_target, 'auth')
print 'Active Session: ' + zap.httpsessions.active_session(api_target)


# Add Authorization Header
for rule in zap.replacer.rules:
    zap.replacer.remove_rule(rule['description'])
zap.replacer.add_rule('Authorization Header', True, 'REQ_HEADER', False, 'Authorization', 'Bearer ' + auth_token)
zap.replacer.add_rule('Cookie', True, 'REQ_HEADER', False, 'Cookie', 'AWSALB=' + awsalb + ';JSESSIONID=' + jsessionid)
print ('Replacer Rules: ' + str(len(zap.replacer.rules)))


# Spider Scan
print('Spidering targets...')
zap.spider.exclude_from_scan('\Q/v2/api/signin\E.*')
zap.spider.exclude_from_scan('\Q/v2/api/signout\E.*')
zap.urlopen(admin_target)
admin_scanid = zap.spider.scan(url=admin_target, recurse=True, maxchildren=6)
while (int(zap.spider.status(admin_scanid)) < 100):
    # Loop until the spider has finished
    print('Spider progress on {} %: {}'.format(admin_target, zap.spider.status(admin_scanid)))
    time.sleep(2)
print 'Added ' + str(len(zap.spider.added_nodes(admin_scanid))) + ' URLs'
scanid = zap.spider.scan(url=api_target, recurse=True, maxchildren=6)
while (int(zap.spider.status(scanid)) < 100):
    # Loop until the spider has finished
    print('Spider progress on {} %: {}'.format(api_target, zap.spider.status(scanid)))
    time.sleep(2)
print 'Added ' + str(len(zap.spider.added_nodes(scanid))) + ' URLs'
print ('Spider completed')


# Get URLs from Swagger (API-Docs)
count = 0
try:
    print 'Downloading Swagger API definition...'
    api_docs = requests.get(api_url + '/v2/api-docs', cookies=cookies)
    api_content = json.loads(api_docs.content)
    paths = api_content['paths']
    for url in paths:
        new_temp_url = url.replace('{', '%7B')
        final_url = new_temp_url.replace('}', '%7D')
        if api_target.strip('/') + final_url in zap.core.urls():
            continue
        if ('/v2/api/signin' or '/v1/api/signout') in final_url:
            print ('Skipping URL ' + final_url)
            continue
        print 'Adding URL ' + api_target.strip('/') + final_url
        count += 1
        zap.urlopen(api_target.strip('/') + final_url)
except Exception:
    print 'Swagger (API-Docs) Failure for ' + api_hostname
    #exit(1)

if count > 0:
    print 'Imported ' + str(count) + ' new URLs from Swagger'


# Active Scan
print ('Starting Active Scan...')
zap.ascan.enable_all_scanners('Server Security')
zap.ascan.set_enabled_policies(ids=2, scanpolicyname='Server Security')
print ('Scanning ' + admin_target)
scanid = zap.ascan.scan(url=admin_target, recurse=True, inscopeonly=True)
while (int(zap.ascan.status(scanid)) < 100):
    # Loop until the scanner has finished
    time.sleep(1)
for msg_id in zap.ascan.messages_ids(scanid):
    print '>> ' + zap.core.message(msg_id)['requestHeader'].split(' HTTP')[0]
    response = zap.core.message(msg_id)['responseHeader'].split('\r\n')[0]
    print '>> ' + response
    if '301' in response:
        if 'Location:' in response:
            if 'Location: http:' not in response:
                loc_temp = zap.core.message(msg_id)['responseHeader'].split('Location: ')[1]
                print '>> Location: ' + loc_temp.split('\r\n')[0]
print ('Scanning ' + api_target)
scanid = zap.ascan.scan(url=api_target, recurse=False, inscopeonly=False, scanpolicyname='Server Security')
while (int(zap.ascan.status(scanid)) < 100):
    # Loop until the scanner has finished
    time.sleep(1)
for msg_id in zap.ascan.messages_ids(scanid):
    print zap.core.message(msg_id)['requestHeader'].split(' HTTP')[0]
    print zap.core.message(msg_id)['responseHeader'].split('\r\n')[0]
print ('Active Scan completed')


# Build Report
pass_count = 0
warn_count = 0
fail_count = 0
ignore_count = 0
report_string = 'Total of {} URLs\n\n'.format(len(zap.core.urls()))
alert_dict = {}
alerts = zap.core.alerts()
for alert in alerts:
    plugin_id = alert.get('pluginId')
    if (not alert_dict.has_key(plugin_id)):
        alert_dict[plugin_id] = []
    alert_dict[plugin_id].append(alert)
all_rules = zap.pscan.scanners  # AScan rules not considered PASS by default
# Passing rules
pass_dict = {}
for rule in all_rules:
    plugin_id = rule.get('id')
    if (not alert_dict.has_key(plugin_id)):
        pass_dict[plugin_id] = rule.get('name')
for key, rule in sorted(pass_dict.iteritems()):
    report_string += 'PASS: ' + rule + ' [' + key + ']\n'
pass_count = len(pass_dict)
# Failing rules
for key, alert_list in sorted(alert_dict.iteritems()):
    if key == 'IGNORE':
        action = 'IGNORE'
        ignore_count += 1
    elif key == 'FAIL':
        action = 'FAIL'
        fail_count += 1
    else:
        action = 'WARN'
        warn_count += 1
    report_string += (action + ': {} [{}] x ' + str(len(alert_list))
                      + '\n').format(alert_list[0].get('alert'), alert_list[0].get('pluginId'))
    # Show first 5 urls
    for alert in alert_list:
    #for alert in alert_list[0:5]:
        report_string += ('\t' + alert.get('url') + '\n')


# Print Report
print ('\nSummary: ')
print ('FAIL:   ' + str(fail_count))
print ('WARN:   ' + str(warn_count))
print ('IGNORE: ' + str(ignore_count))
print ('PASS:   ' + str(pass_count))
print (report_string)

