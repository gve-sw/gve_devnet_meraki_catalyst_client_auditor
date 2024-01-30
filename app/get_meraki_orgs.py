import meraki
import json
import os
from dotenv import load_dotenv

# load all environment variables
load_dotenv()

dashboard = meraki.DashboardAPI(api_key=os.environ["MERAKI_API_TOKEN"],output_log=False)
orgs = dashboard.organizations.getOrganizations()

# Export the organizations to a JSON file
with open('organizations.json', 'w') as file:
    json.dump(orgs, file, indent=4)

print("Organizations data exported to 'organizations.json'")