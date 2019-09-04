import requests
import json
import csv

url = "<Your URL>"

payload = ""
headers = {
	'Accept': "application/json",
	'Content-Type': "application/json",
	'Authorization': "SSWS <API Key>",
	'cache-control': "no-cache"
	}

uid_list=[]

while True:
	response = requests.request("GET", url, data=payload, headers=headers)
	response_header = response.headers
	response_list = json.loads(response.content)
	for j in range(0, len(response_list)):
		row1 = (response_list[j]["id"])
		uid_list.append(row1)
	
	url_len = len(response_header['Link'].split(","))
	if url_len == 1:
		break
	url = response_header['Link'].split(",")[1].split(">")[0].replace('<','')


url = "<Your URL>"
app_admin_url_list=[]
group_admin_url_list=[]

for item in uid_list:
	app_admin_url = url + "/"+ item + "/roles/<your ROLE ID for the app admins>/targets/catalog/apps"
	app_admin_url_list.append(app_admin_url)
	
app_admin_response_list=[]

for app_admin_url in app_admin_url_list:
	app_admin_response = requests.request("GET", app_admin_url, data=payload, headers=headers)
	app_parse = json.loads(app_admin_response.content)
	clean_uid = app_admin_url.split("/")[6]

	if isinstance(app_parse,list):
		app_admin_response_list.extend([app_parse,clean_uid])
		
uid_final = app_admin_response_list[1::2]
response_app_admin_list = app_admin_response_list[0::2]
response_app_admin=[]
response_app_admin.append(response_app_admin_list)


with open("okta2_app_admin_lookup.csv", "w") as aafile:
	aafilelist = csv.writer(aafile,delimiter=',', quoting=csv.QUOTE_NONE)
	headers = ["app_name","uid"]
	aafilelist.writerow(headers)
	for item in response_app_admin:
		for i in range(0, len(item)):
			for sub_item in item[i]:
				aafilelist.writerow([sub_item['name'],uid_final[i]])



def send_message_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_message_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_message_1' call
    # formatted_data_1 = phantom.get_format_data(name='Send_Pan_traffic_Result')

    # collect data for 'send_slack_message1' cal8l
    
    results_data = phantom.collect2(container=container, datapath=['run_query_1:action_result.data.*.count','run_query_1:action_result.data.*.action', 'run_query_1:action_result.data.*.src_ip', 'run_query_1:action_result.data.*.dest_ip', 'run_query_1:action_result.data.*.dest_port','run_query_1:action_result.data.*.src_zone', 'run_query_1:action_result.data.*.dest_zone'], action_results=results)

     # collect data from artifacts for Risky IP
    results_data1 = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress','artifact:*.cef.risk_score'], action_results=results)
    parameters = []
    phantom.debug(results_data)
    for results_item in results_data:
        for results_item1 in results_data1:
            if results_item[0]:
                risk_ip = results_item1[0]
                risk_score = results_item1[1]
                count = results_item[0]
                action = results_item[1]
                src_ip = results_item[2]
                dest_ip = results_item[3]
                dest_port = results_item[4]
                src_zone = results_item[5]
                dest_zone = results_item[6]
                message = ">>> :mag_right: *Recorded Future High Risk IP Alert*\n https://app.recordedfuture.com/live/sc/entity/ip:" + risk_ip + " \n risk score: `"+ risk_score +"`\n" + " log source: `palo:traffic` \n src_ip: `" + src_ip + "` \n src_zone:`"+ src_zone + "` \n dest_ip: `" + dest_ip + "` \n dest_zone: `" + dest_zone+ "` \n dest_port: `" + dest_port + "` \n event_count: `" + count + "` \n firewall action : `" + action + "` \n container_id: `" + str(container["id"]) + "`"
                phantom.debug(message)
            # build parameters list for 'send_message_1' call      
        parameters.append({
            'destination': "infosec-alerts",
            'message': message 
        })
    phantom.debug(parameters)
    phantom.act("send message", parameters=parameters, app={ "name": 'Slack' }, name="send_message_1", parent_action=action)

    return

def send_message_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_message_3() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_message_3' call
    results_data_1 = phantom.collect2(container=container, datapath=['Splunk_DHCP_search:action_result.data.*._raw', 'Splunk_DHCP_search:action_result.data.*._time'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress'])

    parameters = []
    
    # build parameters list for 'send_message_3' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            if results_item_1[0]:
                parameters.append({
                    'destination': "@infosec-alerts",
                    'message': "The High Risk IP `" + results_item_2[0] + "` was reached from IP with the DHCP record of `" + results_item_1[0] + "` with the timestamp `" + results_item_1[1] + "`",
                    # context (artifact id) is added to associate results with the artifact
                    #'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act("send message", parameters=parameters, app={ "name": 'Slack' }, name="send_message_3")

    return

def SPL_PAN(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('SPL_PAN() called')
    
    template = """index=networking sourcetype=\"pan:traffic\" {0} earliest=-4h |stats count by src_ip, dest_ip,dest_port, action, src_zone, dest_zone"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="SPL_PAN")

    run_query_1(container=container)

    return
