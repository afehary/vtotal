import requests
import time
from portscanner import validate_ip
from utils import timefunc

# Replace the API key with an environment variable for security (recommended)
keys = "57e3ad8188a5a8581df9deacf2824f8082938b3ff9a6f90d819595ea0f0e0fb5"

urls = "https://www.virustotal.com/api/v3/"

@timefunc
def analyze(response):
    while True:
        response_json = response.json()
        stats = response_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", None)
        if not stats:
            analysis_id = response.json()["data"]["id"]
            url = f"{urls}analyses/{analysis_id}"

            headers = { 
                "accept" : "application/json",
                "x-apikey": keys
            }

            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                json_response = response.json()
                status = json_response["data"]["attributes"]["status"]
                stats = json_response["data"]["attributes"]["stats"]
                if status == "completed":
                    pass

                elif status == "in-progress" or status == "queued":
                    print(f"Status: {status}. Waiting for analysis to complete...")
                    json_response = response.json()
                    stats = json_response["data"]["attributes"]["stats"]
                    time.sleep(10)
                else:
                    print(f"Analysis failed with status: {status}")
                    break

            else:
                print(f"Failed: {url} {response.status_code} - {response.text}")
                break

        if stats:
            status = "completed"
            print(f"Status: {status}")
            print(f"Harmless: {stats.get('harmless', 0)}")
            print(f"Malicious: {stats.get('malicious', 0)}")
            print(f"Suspicious: {stats.get('suspicious', 0)}")
            print(f"Undetected: {stats.get('undetected', 0)}")
            print(f"Timeout: {stats.get('timeout', 0)}")
            break
        else:
            print(f"Failed: {url} {response.status_code} - {response.text}")
            break

def scan_file():
    
    file_path = input("Enter the file path: ")
    url = f"{urls}files"
    files = {"file": open(file_path, "rb")}
    headers = {
        "accept": "application/json",
        "x-apikey": keys
    }

    response = requests.post(url, files=files, headers=headers)
    if response.status_code == 200:
        return analyze(response)
    else:
        print('Error: ', response.text)

def scan_url():
    your_url = input("Enter the URL: ")
    url = f"{urls}urls"
    payload = {"url": your_url}
    headers = {
        "accept": "application/json",
        "x-apikey": keys,
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers)
    if response.status_code == 200:
        return analyze(response)
    else:
        print('Error: ', response.text)

def get_file_report():
    hash_option = input("Enter (a) for SHA-256 hash or (b) for SHA-1 hash or (c) for MD5 hash: ")
    hash_value = ""
    if hash_option == 'a':
        hash_value = input("Enter the SHA-256 hash: ")
    elif hash_option == 'b':
        hash_value = input("Enter the SHA-1 hash: ")
    elif hash_option == 'c':
        hash_value = input("Enter the MD5 hash: ")
    else:
        print("Invalid option. Please try again.")
        return

    url = f"{urls}files/{hash_value}"
    headers = {
        "accept": "application/json",
        "x-apikey": keys
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return analyze(response)
    else:
        print('Error: ', response.text)

def get_url_report():
    url_to_analyze = input("Enter the URL: ")
    url = f"{urls}urls"
    payload = {"url": url_to_analyze}
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": keys
    }

    response = requests.post(url, data=payload, headers=headers)
    if response.status_code == 200:
        return analyze(response)
    else:
        print('Error: ', response.text)

def get_domain_report():
    domain = input("Enter Domain name: ")
    if domain:
        url = f"{urls}domains/{domain}"
        headers = {"accept": "application/json", "x-apikey": keys}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
             analyze(response)
        else:
            print('An error: ', response.text)
    else:
        print('Enter a valid domain')

def get_ip_report():
    ip = input("Provide IP: ")
    if validate_ip(ip):
        url = f"{urls}ip_addresses/{ip}"
        headers = {"accept": "application/json", "x-apikey": keys}

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            analyze(response)
        else:
            print(f'An error: {ip}', response.text)
    else:
        print("Invalid IP address")

def main():
    option = input("Enter (1) to upload a file to scan \n"
                   "Enter (2) to upload a URL to scan \n"
                   "Enter (3) to get a file report by hash \n"
                   "Enter (4) to get a URL analysis report \n"
                   "Enter (5) to get a domain report \n"
                   "Enter (6) to get an IP report \n"
                   "Enter (7) to exit \n: ")
    if option == '1':
        scan_file()
    elif option == '2':
        scan_url()
    elif option == '3':
        get_file_report()
    elif option == '4':
        get_url_report()
    elif option == '5':
        get_domain_report()
    elif option == '6':
        get_ip_report()
    elif option == '7':
        print("Thanks for using vtotal")
        exit()
    else:
        print("Invalid option. Please try again.")
        main()

if __name__ == '__main__':
    main()
