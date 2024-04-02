import requests
import hashlib
import argparse
from time import sleep
from pprint import pprint
import os

try:
    from key import API_KEY
except ImportError:
    API_KEY = "add your API key here"

HEADERS = {"x-apikey": API_KEY}

def hash_it(file, algorithm):
    # Function to calculate hash of the file
    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    elif algorithm == "md5":
        hasher = hashlib.md5()
    else:
        raise Exception(
            "Incompatible hash algorithm used. Choose from: sha256 | sha1 | md5")

    with open(file, 'rb') as f:
        hasher.update(f.read())
    return hasher.hexdigest()

def vt_get_data(f_hash):
    # Function to get data against the file hash provided from the VirusTotal API
    url = f"https://www.virustotal.com/api/v3/files/{f_hash}"
    while True:
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    return response

def vt_post_files(file, url="https://www.virustotal.com/api/v3/files"):
    # Function to upload a file to VirusTotal for analysis and return the response
    with open(file, "rb") as f:
        file_bin = f.read()
    upload_package = {"file": (os.path.basename(file), file_bin)}
    timeout = 300  # Set timeout to 5 minutes (adjust as needed)
    while timeout > 0:
        print("Uploading file to VirusTotal...")
        response = requests.post(url, headers=HEADERS, files=upload_package)
        if error_handle(response):
            break
        timeout -= 1
        sleep(1)
    return response

def vt_get_analyses(response):
    # Function to return the file hash of the uploaded file once the analysis is available
    _id = response.json().get("data").get("id")
    url = f"https://www.virustotal.com/api/v3/analyses/{_id}"
    while True:
        sleep(60)
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    if response.json().get("data").get("attributes").get("status") == "completed":
        f_hash = response.json().get("meta").get("file_info").get("sha256")
        return f_hash

def vt_get_upload_url():
    # Function to return a URL to upload files larger than 32MB to VirusTotal
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    while True:
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    return response.json()["data"]

def error_handle(response):
    # Function to handle errors in the response
    if response.status_code == 429:
        sleep(60)
    if response.status_code == 401:
        raise Exception("Invalid API key")
    elif response.status_code not in (200, 404, 429):
        raise Exception(response.status_code)
    else:
        return True
    return False

def parse_response(response):
    # Function to parse response from the VirusTotal API
    json_obj = response.json().get("data").get("attributes")

    output = {}

    output["name"] = json_obj.get("meaningful_name")
    output["stats"] = json_obj.get("last_analysis_stats")
    output["engine_detected"] = {}

    for engine in json_obj.get("last_analysis_results").keys():
        if json_obj.get("last_analysis_results").get(engine).get("category") != "undetected":
            output.get("engine_detected")[engine] = {}
            output.get("engine_detected")[engine]["category"] = json_obj.get(
                "last_analysis_results").get(engine).get("category")
            output.get("engine_detected")[engine]["result"] = json_obj.get(
                "last_analysis_results").get(engine).get("result")

    output["votes"] = json_obj.get("total_votes")
    output["hash"] = {"sha1": json_obj.get(
        "sha1"), "sha254": json_obj.get("sha256")}
    output["size"] = json_obj.get("size")
    return output

def bar(parsed_response):
    # Function to generate a bar to visually represent the engine detection
    total = 72
    undetected = parsed_response.get("stats").get("undetected")
    data = f"{'@'*undetected}{' '*(total-undetected)}"
    bar = f"+{'-'*total}+\n|{data}| {undetected}/{total} did not detect\n+{'-'*total}+"
    return bar

def main():
    parser = argparse.ArgumentParser(description="Scan files with VirusTotal")
    parser.add_argument("--output", "-o", help="Output file path", default="vt_scan_results.txt")
    args = parser.parse_args()

    output_file_path = args.output

    with open(output_file_path, "w") as output_file:
        current_dir = os.getcwd()
        print(f"Current directory: {current_dir}")
        for root, dirs, files in os.walk(current_dir):
            for file_name in files:
                if file_name.endswith(".txt"):  # Skip .txt files
                    continue
                file_path = os.path.join(root, file_name)
                print(f"Scanning file: {file_name}")
                file_hash = hash_it(file_path, "sha256")
                response = vt_get_data(file_hash)

                if response.status_code == 404:
                    if os.path.getsize(file_path) > 32000000:
                        response = vt_get_data(vt_get_analyses(vt_post_files(file_path, vt_get_upload_url())))
                    else:
                        response = vt_get_data(vt_get_analyses(vt_post_files(file_path)))

                if response.status_code == 200:
                    parsed_response = parse_response(response)
                    url = f"https://www.virustotal.com/gui/file/{parsed_response['hash']['sha254']}/detection"

                    output_file.write(f"File: {file_name}\n")
                    output_file.write(f"Detection Results URL: {url}\n")
                    output_file.write(f"SHA256 Hash: {parsed_response['hash']['sha254']}\n")
                    output_file.write("Detections:\n")
                    for engine, result in parsed_response['engine_detected'].items():
                        output_file.write(f"  {engine}: {result['category']} - {result['result']}\n")
                    output_file.write("\n")

                    pprint(parsed_response, indent=2)
                    print()
                    print(bar(parsed_response))
                else:
                    raise Exception(f"Error scanning file {file_name}, status code: {response.status_code}")

    input("Press Enter to exit...")

if __name__ == "__main__":
    main()
