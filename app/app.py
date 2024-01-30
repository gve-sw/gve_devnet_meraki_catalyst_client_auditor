""" Copyright (c) 2024 Cisco and/or its affiliates.
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

# Import Section
from flask import Flask, render_template, request, url_for, redirect, jsonify,session
from collections import defaultdict
import datetime
import requests
import json
from dotenv import load_dotenv
import os
import merakiAPI
from netmiko import ConnectHandler
import json
import re
import csv
from flask import make_response
from io import StringIO

# load all environment variables
load_dotenv()


# Global variables
app = Flask(__name__)

def update_devices_json(devices):
    with open('app/devices.json', 'r') as file:
        current_devices = json.load(file)
    current_devices.extend(devices)
    with open('app/devices.json', 'w') as file:
        json.dump(current_devices, file, indent=4)

# Methods
# Returns location and time of accessing device
def getSystemTimeAndLocation():
    # request user ip
    userIPRequest = requests.get('https://get.geojs.io/v1/ip.json')
    userIP = userIPRequest.json()['ip']

    # request geo information based on ip
    geoRequestURL = 'https://get.geojs.io/v1/ip/geo/' + userIP + '.json'
    geoRequest = requests.get(geoRequestURL)
    geoData = geoRequest.json()
    
    #create info string
    location = geoData['country']
    timezone = geoData['timezone']
    current_time=datetime.datetime.now().strftime("%d %b %Y, %I:%M %p")
    timeAndLocation = "System Information: {}, {} (Timezone: {})".format(location, current_time, timezone)
    
    return timeAndLocation

def get_all_keys(json_data):
    all_keys = set()
    for entry in json_data:
        all_keys.update(entry.keys())
    return list(all_keys)

def get_next_id():
    with open('app/devices.json', 'r') as file:
        current_devices = json.load(file)
    if current_devices:
        last_device = max(current_devices, key=lambda x: x['id'])
        return last_device['id'] + 1
    else:
        return 1


#Read data from json file
def getJson(filepath):
	with open(filepath, 'r') as f:
		json_content = json.loads(f.read())
		f.close()

	return json_content

#Write data to json file
def writeJson(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f)
    f.close()

# Helper functions to handle JSON file operations
def get_devices():
    try:
        with open('app/devices.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_devices(devices):
    with open('app/devices.json', 'w') as f:
        json.dump(devices, f, indent=4)

def load_devices():
    with open('app/devices.json', 'r') as file:
        return json.load(file)

def get_hostname_by_device_id(device_id, devices):
    device = next((d for d in devices if str(d['id']) == str(device_id)), None)
    return device['hostname'] if device else None

def read_mac_address_table(hostname):
    try:
        with open(f'app/mac_address_tables/{hostname}.txt', 'r') as file:
            return file.read()
    except FileNotFoundError:
        print(f"MAC address table file for {hostname} not found.")
        return None
def parse_mac_address_table(mac_table_content):
    # Regular expression to match VLAN, MAC, and Ports from the MAC address table
    mac_table_regex = re.compile(r'(\d+)\s+([0-9a-fA-F.]+)\s+\w+\s+(\S+)')
    return mac_table_regex.findall(mac_table_content)

def get_meraki_clients_normalized(meraki_clients):
    # Normalize the MAC addresses from the Meraki clients
    return [{**client, 'mac': normalize_mac(client['mac'])} for client in meraki_clients]

def normalize_mac(mac):
    # Remove any non-alphanumeric characters (like . or :)
    return ''.join(filter(str.isalnum, mac)).lower()  # Convert to lowercase for case-insensitive comparison

##Routes

@app.route('/', methods=['GET', 'POST'])
def meraki():
    try:
        merakiAPI.authenticate()  # Ensure you're authenticated
        # Fetch the switches and networks regardless of the method to display them on the page
        switch_devices = get_devices()

        # Fetch networks based on the selected organization
        selected_org = os.environ["MERAKI_ORG_ID"]
        meraki_networks = merakiAPI.getNetworks(selected_org)

        # If it's a POST request, process the form submission
        if request.method == 'POST':
            selected_switches = request.form.getlist('switches')
            selected_networks = request.form.getlist('networks')
            results = process_selections(selected_switches, selected_networks)
            print(results)
            
            # Format each entry in the results
            formatted_results = []
            for entry in results:
                formatted_entry = {key: value for key, value in entry.items()}
                formatted_results.append(formatted_entry)

            # Pass the results and the original data back to the template
            return render_template('merakiAPI.html', switches=switch_devices, networks=meraki_networks, results=formatted_results, selected_org=selected_org,hiddenLinks=False, timeAndLocation=getSystemTimeAndLocation())

        # For a GET request, just render the page with switches and networks
        return render_template('merakiAPI.html', switches=switch_devices, networks=meraki_networks, hiddenLinks=False, selected_org=selected_org,timeAndLocation=getSystemTimeAndLocation())

    except Exception as e:
        print(e)
        return render_template('merakiAPI.html', hiddenLinks=False, error=True, errormessage=str(e), timeAndLocation=getSystemTimeAndLocation())

@app.route('/meraki_api', methods=['POST'])
def process_meraki_api():
    try:
        # Retrieve the selected organization from the form or session
        selected_org = request.form.get('organization')
        
        # If there's no selected organization, redirect to the / page or handle it appropriately
        if not selected_org:
            # Handle the case where there is no selected organization
            return redirect(url_for('/'))

        # Fetch the switches and networks again to display them on the page
        switch_devices = get_devices()
        meraki_networks = merakiAPI.getNetworks(selected_org)

        # Process the selected switches and networks
        selected_switches = request.form.getlist('devices')
        selected_networks = request.form.getlist('networks')
        results = process_selections(selected_switches, selected_networks)
        
        with open('app/results.json', 'w') as file:
            print("saving results")
            json.dump(results, file)

        # Render the template with the results and the original data
        return render_template('merakiAPI.html', switches=switch_devices, networks=meraki_networks, results=results,selected_org=selected_org, hiddenLinks=False, timeAndLocation=getSystemTimeAndLocation())
    except Exception as e:
        print(e)
        return render_template('merakiAPI.html', hiddenLinks=False, error=True, errormessage=str(e), timeAndLocation=getSystemTimeAndLocation())



def process_selections(switches, networks):
    if len(switches) == 0 and len(networks) == 0:
        return f"Processed {len(switches)} switches and {len(networks)} networks."
    else:
        print(switches)
        print(networks)
        devices = load_devices()
        detailed_results = []

        # Parse MAC address tables for selected switches
        for switch_id in switches:
            hostname = get_hostname_by_device_id(switch_id, devices)
            if hostname:
                mac_table_content = read_mac_address_table(hostname)
                if mac_table_content:
                    mac_entries = parse_mac_address_table(mac_table_content)
                    # Process each MAC entry
                    for vlan, mac_address, port in mac_entries:
                        mac_address = normalize_mac(mac_address)
                        # Initialize a flag to track if the MAC address is found in Meraki data
                        mac_found_in_meraki = False
                        
                        # Query the Meraki API for each network
                        for network_id in networks:
                            meraki_clients = merakiAPI.getClientsByNetwork(network_id)
                            normalized_meraki_clients = get_meraki_clients_normalized(meraki_clients)
                            
                            # Find matching clients by MAC address
                            for client in normalized_meraki_clients:
                                if client['mac'] == mac_address:
                                    # A client with the MAC address is found in Meraki data
                                    mac_found_in_meraki = True
                                    
                                    # If VLANs do not match, add to the detailed results
                                    if vlan != client.get('vlan'):
                                        detailed_results.append({
                                            'switch_hostname': hostname,
                                            'vlan': vlan,
                                            'mac_address': mac_address,
                                            'switch_port': port,
                                            'meraki_network_id': network_id,
                                            'meraki_device_name': client.get('recentDeviceName', 'Unknown'),
                                            'meraki_device_port': client.get('switchport', 'Unknown'),
                                            'meraki_device_vlan': client.get('vlan', 'Unknown')
                                        })
                                    # If VLANs match, break out of the loop and do not add to results
                                    break
                        
                        # If the MAC address was not found in Meraki data at all, add to the detailed results
                        if not mac_found_in_meraki:
                            detailed_results.append({
                                'switch_hostname': hostname,
                                'vlan': vlan,
                                'mac_address': mac_address,
                                'switch_port': port,
                                'client_not_found': True
                            })
                else:
                    detailed_results.append(f"MAC table for {hostname} not found.")
            else:
                detailed_results.append(f"Hostname for device ID {switch_id} not found.")

        # Return detailed results
        return detailed_results



# Global list to store devices. In a real application, this should be a database.
devices = []
def create_devices(store_number):
    devices = []
    # Start the ID count based on the existing devices in the JSON.
    start_id = get_next_id()

    # Creating 2 L3 and 6 L2 devices as per the pattern in your JSON.
    for i in range(1, 3):  # L3 Switches
        devices.append({
            'id': start_id,
            'hostname': f'SR{store_number}{i}',
            'username': os.environ["SSH_USERNAME"],
            'password': os.environ["SSH_PASSWORD"],
            'connection': False,
            'mac_table_saved': False
        })
        start_id += 1
    
    for i in range(3, 9):  # L2 Switches
        devices.append({
            'id': start_id,
            'hostname': f'SW{store_number}{i}',
            'username': os.environ["SSH_USERNAME"],
            'password': os.environ["SSH_PASSWORD"],
            'connection': False,
            'mac_table_saved': False
        })
        start_id += 1
    
    return devices

@app.route('/manage_devices')
def manage_devices():
    devices = get_devices()
    return render_template('manageDevices.html', devices=devices)

@app.route('/export-csv')
def export_csv():
    # Read the results from the JSON file
    with open('app/results.json', 'r') as file:
        json_data = json.load(file)

    # Get all keys
    all_keys = get_all_keys(json_data)

    # Convert to CSV
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(all_keys)  # Write headers

    for item in json_data:
        row = [item.get(key, "") for key in all_keys]  # Use get() to handle missing keys
        cw.writerow(row)

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=results.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/add_devices', methods=['POST'])
def add_devices():
    store_number = request.form['store_number']
    devices = create_devices(store_number)
    update_devices_json(devices)
    return redirect(url_for('manage_devices'))


@app.route('/add_device', methods=['POST'])
def add_device():
    devices = get_devices()
    new_device = {
        'id': max([device['id'] for device in devices], default=0) + 1,
        'hostname': request.form['hostname'],
        'username': request.form['username'],
        'password': request.form['password'],
        'connection' : False,
        'mac_table_saved' : False
        }
    devices.append(new_device)
    save_devices(devices)
    return redirect(url_for('manage_devices'))

@app.route('/edit_device/<int:device_id>', methods=['GET', 'POST'])
def edit_device(device_id):
    devices = get_devices()
    device_to_edit = next((device for device in devices if device['id'] == device_id), None)
    if device_to_edit is None:
        return "Device not found", 404

    if request.method == 'POST':
        device_to_edit['hostname'] = request.form['hostname']
        device_to_edit['username'] = request.form['username']
        device_to_edit['password'] = request.form['password']
        save_devices(devices)
        return redirect(url_for('manage_devices'))

    return render_template('editDevice.html', device=device_to_edit)

@app.route('/delete_device/<int:device_id>')
def delete_device(device_id):
    devices = get_devices()
    devices = [device for device in devices if device['id'] != device_id]
    save_devices(devices)
    return redirect(url_for('manage_devices'))

@app.route('/test_connection/<int:device_id>', methods=['POST'])
def test_connection(device_id):
    try:
        with open('app/devices.json', 'r') as file:
            devices = json.load(file)
    except IOError as e:
        print(f"Error reading from devices.json: {e}")
        return jsonify({'success': False, 'error': 'Could not read devices file'}), 500

    # Find the index of the device in the list
    device_index = next((i for i, device in enumerate(devices) if device['id'] == device_id), None)
    if device_index is None:
        return jsonify({'success': False, 'error': 'Device not found'}), 404

    # Use the index to access the device directly from the devices list
    device_to_test = devices[device_index]

    try:
        # Use Netmiko to attempt a connection
        connection = ConnectHandler(
            device_type='cisco_ios',
            host=device_to_test['hostname'],
            username=device_to_test['username'],
            password=device_to_test['password'],
            #timeout=5  # Short timeout for testing purposes
        )
        connection.disconnect()
        devices[device_index]['connection'] = True  # Update the devices list directly
    except Exception as e:
        print(f"Error connecting to device: {e}")
        devices[device_index]['connection'] = False  # Update the devices list directly
        return jsonify({'success': False, 'connection': devices[device_index]['connection']})

    try:
        # Write the updated devices list back to the file
        with open('app/devices.json', 'w') as file:
            json.dump(devices, file, indent=4)
    except IOError as e:
        print(f"Error writing to devices.json: {e}")
        return jsonify({'success': False, 'error': 'Could not write to devices file'}), 500

    return jsonify({'success': True, 'connection': devices[device_index]['connection']})



@app.route('/execute_show_mac', methods=['POST'])
def execute_show_mac():
    # Dummy data for demonstration; replace with actual form data processing
    devices_info = json.loads(request.form['devices_info'])
    
    # Call the modified get_show_mac function and pass the devices info
    results = get_show_mac(devices_info)
    
    # Return the results as JSON
    return jsonify(results)

@app.route('/get_show_mac/<int:device_id>', methods=['POST'])
def get_show_mac(device_id):
    # Load the devices from the JSON file
    with open('app/devices.json', 'r') as file:
        devices = json.load(file)

    # Find the index of the device by ID
    device_index = next((i for i, device in enumerate(devices) if device['id'] == device_id), None)
    if device_index is None:
        return jsonify({'success': False, 'error': 'Device not found'}), 404

    try:
        # Set up the device connection details
        device = devices[device_index]  # Direct reference to the device in the devices list
        connection_details = {
            "device_type": "cisco_ios",
            "host": device['hostname'],
            "username": device['username'],
            "password": device['password'],
            "port": 22,
        }
        
        # Connect to the device and send the command
        connection = ConnectHandler(**connection_details)
        mac_table = connection.send_command('show mac address-table')
        connection.disconnect()

        # Save the output to a file
        os.makedirs('app/mac_address_tables', exist_ok=True)
        filename = f'app/mac_address_tables/{device["hostname"]}.txt'
        with open(filename, 'w') as file:
            file.write(mac_table)

        # Update the 'mac_table_saved' field for the device
        devices[device_index]['mac_table_saved'] = True

        # Write the updated devices list back to the JSON file
        with open('app/devices.json', 'w') as file:
            json.dump(devices, file, indent=4)

        return jsonify({'success': True})

    except Exception as e:
        # If an error occurs, update the 'mac_table_saved' field to False
        devices[device_index]['mac_table_saved'] = False
        
        # Write the updated devices list back to the JSON file
        with open('app/devices.json', 'w') as file:
            json.dump(devices, file, indent=4)

        print(e)
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=False)