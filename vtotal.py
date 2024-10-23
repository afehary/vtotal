import requests
import time
from portscanner import validate_ip
from utils import timefunc

# Replace the API key with an environment variable for security (recommended)
keys = "2f40b4e74c499802a15cadcc3a420218f955588932455226e6641d29f0e8720e"

urls = "https://www.virustotal.com/api/v3/"

@timefunc
def analyze(response):
    """
    General function to print a clear, formatted report for VirusTotal analyses.
    Automatically determines the type of resource being analyzed based on the response.
    :param response_json: dict - The JSON response from the VirusTotal API
    """

    analysis_id = None
    stats = None

    # Check if the response requires polling (e.g., files and URLs) or is immediate (e.g., IPs, domains, etc.)
    if "data" in response and "id" in response["data"]:
        analysis_id = response["data"]["id"]
    else:
        # Immediate analysis result, we can extract stats directly
        stats = response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    headers = {
        "x-apikey": keys,
        "accept": "application/json"
    }

    # Use the same loop to handle polling and immediate results
    while True:
        if analysis_id:
            # Polling case: Request the analysis status using the analysis_id
            status_url = f"{urls}analyses/{analysis_id}"
            status_response = requests.get(status_url, headers=headers)

            if status_response.status_code == 200:
                status_json = status_response.json()
                status = status_json["data"]["attributes"]["status"]
                stats = status_json["data"]["attributes"].get("stats", {})

                if status == "completed":
                    break  # Analysis is completed, we can print the stats
                elif status == "queued" or status == "in-progress":
                    print(f"Status: {status}. Waiting for analysis to complete...")
                    time.sleep(10)
                else:
                    print(f"Analysis failed with status: {status}")
                    return  # Exit the function if the analysis fails
            else:
                print(f"Error fetching analysis: {status_response.status_code} - {status_response.text}")
                return  # Exit the function if there's an error fetching the status
        else:
            # Immediate result case (IPs, domains, etc.), break the loop to print stats
            break

    # Print the stats in a unified format
    if stats:
        print(f"\n==== Analysis Report ====")
        print(f"Harmless: {stats.get('harmless', 0)}")
        print(f"Malicious: {stats.get('malicious', 0)}")
        print(f"Suspicious: {stats.get('suspicious', 0)}")
        print(f"Undetected: {stats.get('undetected', 0)}")
        print(f"Timeout: {stats.get('timeout', 0)}")
        print("=" * 40)
    else:
        print("No last_analysis_stats available in the response.")

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
        response = response.json()
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
        response = response.json()
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
        response = response.json()
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
        response = response.json()
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
             response = response.json()
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
            response = response.json()
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



