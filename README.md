# SSL Labs Scan

This repo was originally forked from [ssllabs-scan](https://github.com/kyhau/ssllabs-scan)

## Addition / Modifications

- Moved from SSL Labs API v2 to v3

- Changed invocation from command line to self-contained script reading from an input text file

- Output of CSV, JSON and HTML files to dedicated folders

- In-line HTML style for report portability

- Fixed failure to generate report when endpoints are uncontactable ("statusMessage")

- Changed default analize API call from startNew="on" to fromCache="on" with a maxAge="1" (one hour for testing)

- Changed scripit to use asyncio / httpx and aiometer

## Description

Support Python >= 3.6

This tool calls the SSL Labs [API v3](https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md) to perform SSL testing on servers.

- **NOTE**: Please note that the SSL Labs Assessment API has access rate limits. You can find more details in the sections "Error Response Status Codes" and "Access Rate and Rate Limiting" in the official [SSL Labs API Documentation](https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md). Some common status codes are:
  - 400 - invocation error (e.g., invalid parameters)
  - 429 - client request rate too high or too many new assessments too fast
  - 500 - internal error
  - 503 - the service is not available (e.g., down for maintenance)
  - 529 - the service is overloaded

## Input and Output

Sample input: [input/hosts.txt](./input/hostst.txt)

1. summary.html (sample output: [output/html/summary.html](./output/html/summary.html))
2. summary.csv (sample output: [output/csv/summary.csv](./output/csv/summary.csv))
3. _hostname_.json (sample output: [output/mas.worldpay.com.json](./output/json/mas.worldpay.com.json))

## Dependencies

- Python >= 3.6
- pip >= 22.0
- httpx >= 0.22.0
- aiometer >=0.3.0


## Run

### Linux / MacOS / Windows

Edit _"./input/hosts.txt"_ to include desired hostnames to be scanned

Run script (Terminal):

```sh
${path_to_python}/python $path_to_script/start_scan.py

```

From VScode:

Select _"start_scan.py"_ then "Terminal -> Run Active File"
