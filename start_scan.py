import asyncio
import aiofiles
import functools
import aiometer
import httpx
import sys
import os
import csv
import json
from datetime import datetime

from templates.report_template import REPORT_HTML

HOST_LIST = "./input/hosts.txt"
INFO_URL = "https://api.ssllabs.com/api/v3/info"
API_URL = "https://api.ssllabs.com/api/v3/analyze"
OUT = "./output"
JSON_DIR = OUT + "/json"
SUMMARY_CSV = OUT + "/csv/summary.csv"
SUMMARY_HTML = OUT + "/html/summary.html"
VAR_TITLE = "{{VAR_TITLE}}"
VAR_DATA = "{{VAR_DATA}}"
DEFAULT_TITLE = "SSL Labs Analysis Summary Report"

CHAIN_ISSUES = {
    "0": "none",
    "1": "unused",
    "2": "incomplete chain",
    "4": "chain contains unrelated or duplicate certificates",
    "8": "the certificates form a chain (trusted or not) but incorrect order",
    "16": "contains a self-signed root certificate",
    "32": "the certificates form a chain but cannot be validated",
}

# Forward secrecy protects past sessions against future compromises of secret keys or passwords.
FORWARD_SECRECY = {
    "1": "With some browsers WEAK",
    "2": "With modern browsers",
    "4": "Yes (with most browsers) ROBUST",
}

PROTOCOLS = [
    "TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0 INSECURE", "SSL 2.0 INSECURE"
]

RC4 = ["Support RC4", "RC4 with modern protocols", "RC4 Only"]

VULNERABILITIES = [
    "Beast", "Drown", "Heartbleed", "FREAK",
    "OpenSSL CCS", "OpenSSL LuckyMinus20", "POODLE", "POODLE TLS"
]

SUMMARY_COL_NAMES = [
    "Host", "Grade", "Warnings", "Cert Expiry", "Chain Status", "Forward Secrecy", "Heartbeat"
] + VULNERABILITIES + RC4 + PROTOCOLS

# Workaround for long standing Python bug (>=3.6) where the Event Loop Policy is not set corrctly under Windows
if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = httpx.AsyncClient()

# Call SSL Labs API for details such as number of current assessments and maximun number of accessments alowed
async def Info():
    url = INFO_URL
    async with httpx.AsyncClient() as client:
        try:
            info = await client.request(method="GET", url=url)
            info.raise_for_status()
        except httpx.HTTPError as exc:
            print(f'Error while requesting {exc.request.url!r}.')
    return info.json()

async def Fetch(client, request):
    try:
        results = await Callapi(client, request)
    except SystemExit:
        print("Caught SystemExit!")
    while results["status"] not in ["READY", "ERROR"]:
        print(f"Status: {results['status']}, wait for 10 seconds...")
        await asyncio.sleep(10)
        results = await Callapi(client, request)
    return results

async def Callapi(client, request):
    i = await Info()
    max_attempts = i["maxAssessments"]
    attempts = i["currentAssessments"]
    await asyncio.sleep(10)
    response = await client.send(request)
    r = str(request)
    h = r.split("host=")[1].split("&")[0]
    print(f"Processing {h}")

    while response.status_code != 200 and attempts < max_attempts:
        delay = 10
        resp = response.status_code
        if resp == "400":
            print(f"Response code: {str(response.status_code)} - Invocation error"
                 f"Exiting the script")
            raise SystemExit(2)
        elif resp == "429":
            print(f"Response code: {str(response.status_code)} - Client request rate too high"
                  f"Waiting 60 sec until next retry...")
            delay == 60
        elif resp == "500":
            print(f"Response code: {str(response.status_code)} - Internal error"
                 f"Exiting the script")
            raise SystemExit(2)    
        elif resp == "503":
            print(f"Response code: {str(response.status_code)} - Service is overloade"
                  f"Exiting the script")
            raise SystemExit(2)
        elif resp == "529":
            print(f"Response code: {str(response.status_code)} - Service is not available"
                 f"Exiting the script")
            raise SystemExit(2)
        else:
            delay = "30"
        if attempts >= max_attempts:
            print(f"Response code: {str(response.status_code)} - Max attemptes reached"
                  f"Waiting 30 minutes until next request")
            delay == 1800
        await asyncio.sleep(delay)
        response = await client.send(request)
    return response.json()

async def Process():
    server_list_file=HOST_LIST
    api = API_URL

    async with aiofiles.open(SUMMARY_CSV, "w") as outfile:
        # write column names to file
        print(f"Summary CSV file created")
        await outfile.write("#{}\n".format(",".join(str(s) for s in SUMMARY_COL_NAMES)))

    # read from input file
    with open(server_list_file) as f:
        content = f.readlines()
    servers = [x.strip() for x in content]

    publish="off"
    fromCache="on"
    maxAge="1"
    all="done"
    ignoreMismatch="on"

    requests = []

    for server in servers:
        payload = {
            "host": server,
            "publish": publish,
            "fromCache": fromCache,
            "maxAge": maxAge,
            "all": all,
            "ignoreMismatch": ignoreMismatch
        }

        requests.append(httpx.Request(method="GET", url=api, params=payload))

    i = await Info()

    """It is important to set the maximun number os requests that can be queued at once, and also the number of actual requets to submit per second.
    The settings below will work well for a maximum of 25 requests at a time (default for the SSL Labs API), but might not be ideal if the
    total number of requests is much larger than 25."""

    async with aiometer.amap(
        functools.partial(Fetch, client),
        requests,
        max_at_once= i["maxAssessments"], # Maybe this is not such a good idea and "max_at_once" should be tweeked when more than 25 URLs are tested? 
        max_per_second=0.5,
    ) as results:
        async for data in results:
            await reports(data)

    print(f"Appending final data to CSV file")
    print(f"Writing data to JSON files")
    print(f"Writing final data to HTML file")

@staticmethod
def prepare_datetime(epoch_time):
    # SSL Labs returns an 13-digit epoch time that contains milliseconds, Python only expects 10 digits (seconds)
    return datetime.utcfromtimestamp(float(str(epoch_time)[:10])).strftime("%Y-%m-%d")

async def reports(data):

    summary_file = SUMMARY_CSV

    #Write data to JSON files
    json_file = os.path.join(JSON_DIR, f"{data['host']}.json")
    outfile = open(json_file, "w")
    json.dump(data, outfile, indent=2)

    #Append data to summary CSV
    async with aiofiles.open(summary_file, 'a') as outfile:
        for ep in data["endpoints"]:
            # Skip endpoints that were not contactable during the scan (e.g. GitHub Pages URLs with IPv6 endpoints)
            if "Unable" in ep["statusMessage"]:
                continue
            # see SUMMARY_COL_NAMES
            summary = [
                data['host'],
                ep["grade"],
                ep["hasWarnings"],
                prepare_datetime(data["certs"][0]["notAfter"]),
                CHAIN_ISSUES[str(ep["details"]["certChains"][0]["issues"])],
                FORWARD_SECRECY[str(ep["details"]["forwardSecrecy"])],
                ep["details"]["heartbeat"],
                ep["details"]["vulnBeast"],
                ep["details"]["drownVulnerable"],
                ep["details"]["heartbleed"],
                ep["details"]["freak"],
                False if ep["details"]["openSslCcs"] == 1 else True,
                False if ep["details"]["openSSLLuckyMinus20"] == 1 else True,
                ep["details"]["poodle"],
                False if ep["details"]["poodleTls"] == 1 else True,
                ep["details"]["supportsRc4"],
                ep["details"]["rc4WithModern"],
                ep["details"]["rc4Only"],
            ]
            for protocol in PROTOCOLS:
                found = False
                for p in ep["details"]["protocols"]:
                    if protocol.startswith(f"{p['name']} {p['version']}"):
                        found = True
                        break
                summary += ["Yes" if found is True else "No"]

            await outfile.write(",".join(str(s) for s in summary) + "\n")

    #Append data to HTML file
    data = ""
    with open(summary_file, "r") as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row[0].startswith("#"):
                data += "  <tr>\n\t<th>{}</th>\n  </tr>".format('</th>\n\t<th>'.join(row))
            else:
                data += '\n  <tr class="{}">\n\t<td>{}</td>\n  </tr>'.format(row[1][:1], '</td>\n\t<td>'.join(row))

    # Replace the target string
    content = REPORT_HTML
    content = content.replace(VAR_TITLE, DEFAULT_TITLE)
    content = content.replace(VAR_DATA, data)

    # Write the file out again
    file = open(SUMMARY_HTML, "w")
    file.write(content)

if __name__ == "__main__":
    import pathlib
    import sys
    assert sys.version_info >= (3, 7), "Script requires Python 3.7+."
    here = pathlib.Path(__file__).parent
    sys.exit(asyncio.run(Process()))