""" Copyright (c) 2020 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
           https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied. 
"""

#How to retrieve an Meraki api key: https://developer.cisco.com/meraki/api-v1/#!getting-started/find-your-organization-id 
#Meraki Dashboard API call documentation: https://developer.cisco.com/meraki/api-v1/#!overview/api-key

# Import Section
import meraki
import os
from dotenv import load_dotenv


def authenticate():
    # load all environment variables
    load_dotenv()

    BASE_URL = "https://api.meraki.com/api/v1"
    global DASHBOARD
    DASHBOARD = meraki.DashboardAPI(
                api_key=os.environ['MERAKI_API_TOKEN'],
                base_url=BASE_URL,
                output_log=False,
                print_console=False)
    
    print(DASHBOARD)
#API calls
#Organizations
def getOrganizations():
    response = DASHBOARD.organizations.getOrganizations()
    return response

#Networks
def getNetworks(orgID):
    response = DASHBOARD.organizations.getOrganizationNetworks(
        orgID, total_pages='all'
    )
    return(response)

#Networks
def getClientsByNetwork(networkID):
    response = DASHBOARD.networks.getNetworkClients(
        networkID, total_pages='all'
    )
    return(response)