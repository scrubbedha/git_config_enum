# Git Repository Enumerator

This script allows you to enumerate open git repositories to identify potential misconfigurations and exposures. It scans in domains from a CSV file and checks if there is a valid `.git/config` file. This tool is designed to be used for security research and is intended to raise awareness about the importance of securing Git repositories.

## Inspiration
This script is inspired by the research conducted by Truffle Security, which revealed that approximately 4,500 out of the top 1 million websites had leaked source code and secrets from their publicly accessible `.git` repositories. The following resources were also used as references related to reconstructing git repos during the development of this tool:

- [Truffle Security Blog: 4500 of the Top 1 Million Websites Leaked Source Code Secrets](https://trufflesecurity.com/blog/4500-of-the-top-1-million-websites-leaked-source-code-secrets/)
- [In a Git Repository: Where do your files live?](https://jvns.ca/blog/2023/09/14/in-a-git-repository--where-do-your-files-live-/)
- [goop by nyancrimew](https://github.com/nyancrimew/goop)
- [trufflehog by Truffle Security](https://github.com/trufflesecurity/trufflehog/)
- [shhgit by eth0izzle](https://github.com/eth0izzle/shhgit)

## Features
- Enumerate open git repositories to remediate potential misconfigurations and exposures.
- Supports CSV files containing domain names for easy scanning of multiple websites.
- Optional proxy server support for anonymous enumeration.
- User-defined User-Agent for HTTP requests.
- Handles SSL errors and timeouts gracefully.

## Installation and Usage
1. Clone the repository:
```bash
git clone https://github.com/scrubbedha/git_config_enum.git
```
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```
3. Run the script with the desired arguments:
```bash
python3 git_config_enum.py [-f --file] top-1m.csv [-x --proxy] <proxy> socks5://user:pass@hostname:port
```
4. The script will scan the provided domains and print the ones that have a valid `.git/config` file.

## Domain Lists
- [Cloudflare Radar Top 1m](https://radar.cloudflare.com/charts/LargerTopDomainsTable/attachment?id=699&top=1000000)
- [Daily 100k Baby Domains/NRDs](https://www.whoisds.com/newly-registered-domains)
```bash
for i in {1..10}; do DATE=$(date -d "$i days ago" '+%Y-%m-%d.zip'); ENCODED=$(echo -n $DATE | base64); curl -s https://www.whoisds.com/whois-database/newly-registered-domains/$ENCODED/nrd -o $DATE; done
for file in newly-*.zip; do unzip -p "$file" domain-names.txt >> all-10d-nrd.csv; done
```
- [Sectigo/crt.sh CT Logs](https://crt.sh/)
```bash
## PostgreSQL - 10,000 most recently issued Let's Encrypt certificates CA_ID 183283 https://crt.sh/?caid=183283
psql -h crt.sh -p 5432 -U guest certwatch -Atc "SELECT row_to_json(t) FROM (SELECT c.ID, c.ISSUER_CA_ID, x509_subjectName(c.CERTIFICATE) SUBJECT_NAME, x509_notBefore(c.CERTIFICATE) NOT_BEFORE, x509_notAfter(c.CERTIFICATE) NOT_AFTER, encode(x509_serialNumber(c.CERTIFICATE), 'hex') SERIAL_NUMBER FROM certificate c WHERE c.ISSUER_CA_ID = 183283::integer ORDER BY NOT_BEFORE DESC OFFSET 0 LIMIT 10000) t" | jq -r '(.subject_name | ltrimstr("CN=") | ltrimstr("*."))' | awk '!seen[$0]++' > le.csv

## All domains like %.azurewebsites.net
curl -s "https://crt.sh/?q=%.azurewebsites.net&output=json" | jq -r '.[] | .common_name | ltrimstr("*.") | ascii_downcase' | awk '!seen[$0]++' > azurewebsites.net.csv
```

## Detections/Hunting
1. YARA
```
rule Detect_Git_Requests
{
    strings:
        $git_requests = /\.git\//

    condition:
        all of them
}
```
2. SIGMA
```
title: Detect .git Requests in Access Logs
id: abcdefgh-ijkl-mnop-qrst-uvwxyz123456
status: experimental
description: Detects requests to the .git directory in web server access logs.
logsource:
    product: webserver
detection:
    selection:
        EventID:
            - web_access_log
    condition: "'GET /\\.git/.*'"
fields:
    - request
falsepositives:
    - Legitimate use of .git folder for non-malicious purposes.
level: high
```
3. Splunk SPL
```
index=<your_webserver_access_logs_index> sourcetype=<your_webserver_access_logs_sourcetype> host=<your_webserver_host> "GET *.git*"
```
4. Kibana KQL
```
index:<your_webserver_access_logs_index> AND (request:*.git* OR request:/.git/*)
```

## Prevention
1. htaccess
```
# Block access to .git directory
RedirectMatch 404 /\.git

# Block access to subdirectories inside .git
RedirectMatch 404 /\.git/.*
```
2. Nginx
```
location ~ /\.git(/|$) {
    deny all;
    return 404;
}
```
3. HAproxy
```
frontend http_front
    bind *:80
    acl acl_git_directory path_reg -i /\.git$
    acl acl_git_subdirectories path_beg /git/

    http-request deny if acl_git_directory
    http-request deny if acl_git_subdirectories
    http-response set-status 404 if acl_git_directory
    http-response set-status 404 if acl_git_subdirectories
```

## Disclaimer
Please use this tool responsibly and only on systems you have proper authorization to test. The script is provided as-is without any warranties or guarantees. The author and contributors are not responsible for any misuse or illegal activities conducted with this tool.

## License
[MIT License](LICENSE)
