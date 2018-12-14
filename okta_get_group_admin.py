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
group_admin_url_list=[]
for item in uid_list:
	group_admin_url = url + "/" + item + "/roles/<Your Group Admin role ID>/targets/groups"
	group_admin_url_list.append(group_admin_url)

group_admin_response_list=[]

for group_admin_url in group_admin_url_list:
	group_admin_response = requests.request("GET", group_admin_url, data=payload, headers=headers)
	group_parse= json.loads(group_admin_response.content)
	clean_uid = group_admin_url.split("/")[6]
	if isinstance(group_parse,list):
		group_admin_response_list.extend([group_parse,clean_uid])

uid_final = group_admin_response_list[1::2]
response_group_admin_list = group_admin_response_list[0::2]
response_group_admin=[]
response_group_admin.append(response_group_admin_list)
counter = 0
with open("okta2_group_admin_lookup.csv", "w") as gafile:
	gafilelist = csv.writer(gafile,delimiter=',', quoting=csv.QUOTE_NONE)
	headers = ["group_name","uid"]
	gafilelist.writerow(headers)
											
	for item in response_group_admin:
		for sub_item in item:
			if len(sub_item)==1:
				for i in range(0,len(sub_item)):
					gafilelist.writerow([sub_item[len(sub_item)-1]['profile']['name'],uid_final[counter]])
					counter+=1
			else:
				for j in range(0,len(sub_item)):
					gafilelist.writerow([sub_item[j]['profile']['name'],uid_final[counter]])
