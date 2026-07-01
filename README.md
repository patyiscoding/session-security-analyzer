winget install gitleaks




The project includes:
- third-party/
    - awesome-regex-list - Regex list used for secrets scanning - https://github.com/Trendyol/awesome-regex-list/tree/main
    - hashcat - Password cracking tool - https://github.com/hashcat/hashcat/tree/master 


Pre-requisites
- (optional, for applications to be run over HTTPS) Nginx

# Starting the tool
`mitmdump -s sessionAnalyzer.py -p 8080 -q --ssl-insecure`
`mitmdump -s sessionAnalyzer.py -p 8080 -q --set ssl_verify_upstream_trusted_ca=..\unified_bundle.pem --set ssl_verify_upstream_trusted_confdir= --set verify_upstream_cert_hostname=false`

Alternatively, the script can be started with the following command:
`mitmdump --set confdir=.`

# NGINX
1. `cd .\nginx`
2. `start nginx`


# Applications
## DVNA
1. `cd .\vulnerable-applications\dvna`
2. `docker run --name dvna -p 1000:9090 -d appsecco/dvna:sqlite`
3. Go to http://localhost:9090

## OWASP Wrong Secrets
1. `docker run -d -p 2000:8080 -p 2001:8090 jeroenwillemsen/wrongsecrets:latest-no-vault`
2. Go to http://localhost:2000

## OWASP JuiceShop
1. `docker pull bkimminich/juice-shop`
2. `docker run -d -p 127.0.0.1:3000:3000 bkimminich/juice-shop`
3. Go to http://localhost:3000

or 

1. `cd .\vulnerable-applications\JuiceShop`
2. `npm start`
3. Go to http://localhost:3000

## Realistic Vulnerable Web Application
1. `cd .\vulnerable-applications\vuln-jwt-lab`
2. `docker build -t jwt-lab .`
3. `docker run -d -p 4000:4000 jwt-lab`
4. Go to http://localhost:4000

<!-- ## Vulnerable-JWT
1. `cd .\vulnerable-applications\Vulnerable-JWT`
2. `npm install`
3. `node app.js`
4. Go to http://localhost:5000 -->

1. `cd .\Vulnerable-Testing-App`
2. `docker build -t vuln-testing-app .`
3. `docker run -d -p 5000:5000 --name running-vuln-app vuln-storage-app`
4. Go to http://localhost:5000

## WebGoat
<!-- must run on 8080 -->
1. `docker run -it -p 127.0.0.1:7000:8080 -p 127.0.0.1:7001:9090 webgoat/webgoat`
2. Go to `http://localhost:7000/WebGoat`



