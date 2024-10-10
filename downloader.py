import json
import subprocess
import requests
from datetime import datetime, timedelta

# constant variables (ask somebody for the API_KEY and SECRET)
API_KEY = "foo" # CHANGE 
SECRET = "bar" # CHANGE
TODAY = (datetime.today() - timedelta(days=1)).strftime('%Y-%m-%d')
REPORT_TYPES = {
    "blocklist",
    "compromised_account",
    "compromised_iot",
    "compromised_iot6",
    "compromised_website",
    "compromised_website6",
    "device_id",
    "device_id6",
    "event4_ddos_participant",
    "event4_honeypot_adb_scan",
    "event4_honeypot_brute_force",
    "event4_honeypot_darknet",
    "event4_honeypot_ddos",
    "event4_honeypot_ddos_amp",
    "event4_honeypot_ddos_target",
    "event4_honeypot_http_scan",
    "event4_honeypot_ics_scan",
    "event4_honeypot_ikev2_scan",
    "event4_honeypot_rdp_scan",
    "event4_honeypot_rocketmq_scan",
    "event4_honeypot_smb_scan",
    "event4_ p_spoofer",
    "event4_microsoft_sinkhole",
    "event4_microsoft_sinkhole_http",
    "event4_sinkhole",
    "event4_sinkhole_dns",
    "event4_sinkhole_http",
    "event4_sinkhole_http_referer",
    "event6_sinkhole",
    "event6_sinkhole_http",
    "event6_sinkhole_http_referer",
    "malware_url",
    "population6_bgp",
    "population6_http_proxy",
    "population6_msmq",
    "population_bgp",
    "population_http_proxy",
    "population_msmq",
    "ransomware_victim",
    "sandbox_conn",
    "sandbox_dns",
    "sandbox_url",
    "scan6_activemq",
    "scan6_bgp",
    "scan6_cwmp",
    "scan6_dns",
    "scan6_elasticsearch",
    "scan6_exchange",
    "scan6_ftp",
    "scan6_http",
    "scan6_http_proxy",
    "scan6_http_vulnerable",
    "scan6_ipp",
    "scan6_isakmp",
    "scan6_ldap_tcp",
    "scan6_mqtt",
    "scan6_mqtt_anon",
    "scan6_mysql",
    "scan6_ntp",
    "scan6_ntpmonitor",
    "scan6_postgres",
    "scan6_rdp",
    "scan6_slp",
    "scan6_smb",
    "scan6_smtp",
    "scan6_smtp_vulnerable",
    "scan6_snmp",
    "scan6_ssh",
    "scan6_ssl",
    "scan6_ssl_freak",
    "scan6_ssl_poodle",
    "scan6_stun",
    "scan6_telnet",
    "scan6_vnc",
    "scan_activemq",
    "scan_adb",
    "scan_afp",
    "scan_amqp",
    "scan_ard",
    "scan_bgp",
    "scan_chargen",
    "scan_cisco_smart_install",
    "scan_coap",
    "scan_couchdb",
    "scan_cwmp",
    "scan_db2",
    "scan_ddos_middlebox",
    "scan_dns",
    "scan_docker",
    "scan_dvr_dhcpdiscover",
    "scan_elasticsearch",
    "scan_epmd",
    "scan_exchange",
    "scan_ftp",
    "scan_hadoop",
    "scan_http",
    "scan_http_proxy",
    "scan_http_vulnerable",
    "scan_ics",
    "scan_ipmi",
    "scan_ipp",
    "scan_isakmp",
    "scan_kubernetes",
    "scan_ldap_tcp",
    "scan_ldap_udp",
    "scan_loop_dos",
    "scan_mdns",
    "scan_memcached",
    "scan_mongodb",
    "scan_mqtt",
    "scan_mqtt_anon",
    "scan_mssql",
    "scan_mysql",
    "scan_nat_pmp",
    "scan_netbios",
    "scan_netis_router",
    "scan_ntp",
    "scan_ntpmonitor",
    "scan_portmapper",
    "scan_post_exploitation_framework",
    "scan_postgres",
    "scan_qotd",
    "scan_quic",
    "scan_radmin",
    "scan_rdp",
    "scan_rdpeudp",
    "scan_redis",
    "scan_rsync",
    "scan_sip",
    "scan_slp",
    "scan_smb",
    "scan_smtp",
    "scan_smtp_vulnerable",
    "scan_snmp",
    "scan_socks",
    "scan_ssdp",
    "scan_ssh",
    "scan_ssl",
    "scan_ssl_freak",
    "scan_ssl_poodle",
    "scan_stun",
    "scan_synfulknock",
    "scan_telnet",
    "scan_tftp",
    "scan_ubiquiti",
    "scan_vnc",
    "scan_ws_discovery",
    "scan_xdmcp",
    "spam_url",
    "special"
}

# global variables
total_requests_count = 1
complete_requests_count = 0
failed_requests_count = 0
failed_requests_array = []

for report_type in REPORT_TYPES:
    
    # Step 1: Create the JSON request 
    request_json = {
        "apikey": f"{API_KEY}",
        "type": f"{report_type}",
        "date": f"{TODAY}"
    }

    json_data = json.dumps(request_json)

    # Step 2: Calculate the HMAC
    hmac_command = f"echo -n '{json_data}' | openssl sha256 -hmac '{SECRET}' -hex"
    hmac_result = subprocess.run(hmac_command, shell=True, capture_output=True, text=True)
    hmac_value = hmac_result.stdout.split()[1]
    headers = {"HMAC2": hmac_value}

    # Step 3: Check if the report exist. If true, retrive and store the table
    request_url = "https://transform.shadowserver.org/api2/reports/list"
    type_response = json.loads((requests.post(request_url, headers=headers, data=json_data)).content)

    print(f"[{total_requests_count}/150] requesting \"{report_type}\"...") 
    total_requests_count += 1
    
    if type_response:
        file_name = type_response[0]["file"]
        file_id = type_response[0]["id"]

        download_url = f"https://dl.shadowserver.org/{file_id}"

        response = requests.post(download_url, headers=headers, data=json_data)

        with open(file_name, 'wb') as output_file:
            output_file.write(response.content)

        complete_requests_count += 1

        print(f"COMPLETED: report does exist, saved to {file_name}")

    else:
        failed_requests_count += 1
        failed_requests_array.append(report_type)

        print(f"FAILED: report does not exist")

    print("\n")

print(f"""\
downloader FINISHED: 
-> total completed requests: {complete_requests_count} 
-> total failed requests: {failed_requests_count} 
   ↪ list of failed requests: {", ".join(failed_requests_array)}
""")