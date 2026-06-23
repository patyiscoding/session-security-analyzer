winget install gitleaks




The project includes:
- third-party/
    - awesome-regex-list - Regex list used for secrets scanning - https://github.com/Trendyol/awesome-regex-list/tree/main
    - hashcat - Password cracking tool - https://github.com/hashcat/hashcat/tree/master 


Pre-requisites
- (optional, for applications to be run over HTTPS) Nginx



# Applications

## OWASP JuiceShop
1. `cd .\JuiceShop`
2. `npm start`
3. Go to http://localhost:3000

## OWASP Wrong Secrets
1. `docker run -p 2000:2000 -p 2010:2010 jeroenwillemsen/wrongsecrets:latest-no-vault`
2. Go to http://localhost:2000

## Realistic Vulnerable Web Application
1. `cd .\vuln-jwt-lab`
2. `docker build -t jwt-lab .`
3. `docker run -p 4000:4000 jwt-lab`
4. Go to http://localhost:4000

## Vulnerable-JWT
1. Browse to the specific folder .\Vulnerable-JWT
2. `npm install`
3. `node app.js`
4. Go to http://localhost:5000













<!-- ## WebGoat
`docker run -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 -e TZ=Europe/Amsterdam webgoat/webgoat`
Go to `http://localhost:8080` -->