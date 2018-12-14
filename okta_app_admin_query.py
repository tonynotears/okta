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
