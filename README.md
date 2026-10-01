SessionAnalyzer is a mitmproxy add-on for performing man-in-the-middle DAST scans. The repository contains the MITM DAST framework core, a vulnerability visualization dashboard, and the testing environment, consisting of a custom-made deliberately vulnerable Vulnerable Testing Application.


The folder structure is as follows:
- nginx: NGINX reverse proxy
- pentagi: PentAGI tool and results
- session-analyzer (this repository)
    - modules/
    - third-party/
        - awesome-regex-list - Regex list used for secrets scanning - https://github.com/Trendyol/awesome-regex-list/tree/main
        - hashcat - Password cracking tool - https://github.com/hashcat/hashcat/tree/master 
    - sessionAnalyzer.py: entry point
    - dashboardServer.py: Vulnerability Dashboard backend
- vulnerability-dashboard
- vulnerable-applications


# Pre-requisites
`pip install -r .\session-analyzer\requirements.txt`

# Options
The framework accepts two command-line options:
- `--set useAttackMode=true` determines whether to run the script in attack mode. Accepted values: `true`, `false`.
- `--set localhostOnly=false` determines whether to run the script against localhost addresses only. Accepted values: `true`, `false`.

# Execution
## Starting the framework
`mitmdump -s sessionAnalyzer.py -p 8888 -q --ssl-insecure`

## Starting the Vulnerability Dashboard
`cd vulnerability-dashboard`  
`npm install`  
`npm run dev`

## Starting NGINX *(optional)*
For testing applications to be run over HTTPS. The following steps are listed for Windows. On Linux, nginx needs to be installed separately.
1. `cd .\nginx`
2. `start nginx`


## Testing environment
### OWASP Wrong Secrets
1. `docker run -d -p 2000:8080 -p 2001:8090 jeroenwillemsen/wrongsecrets:latest-no-vault`
2. Go to http://localhost:2000 or https://localhost:2001

### OWASP JuiceShop
2. `docker run -d -p 3000:3000 bkimminich/juice-shop`
3. Go to http://localhost:3000 or https://localhost:3001

### Realistic Vulnerable Web Application
1. `cd .\vulnerable-applications\vuln-jwt-lab`
2. `docker build -t jwt-lab .`
3. `docker run -d -p 4000:4000 jwt-lab`
4. Go to http://localhost:4000 or https://localhost:4001

### Vulnerable Testing Application
1. `cd .\Vulnerable-Testing-App`
2. `docker build -t vuln-testing-app .`
3. `docker run -d -p 5000:5000 --name running-vuln-app vuln-storage-app`
4. Go to http://localhost:5000 or https://localhost:5001


