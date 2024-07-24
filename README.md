<h1 align="center">📧 Spam Grader: An Email Analysis / Threat Hunting tool 💻</h1>

---

<br />

<h2>Features:</h2>
- Broken into Functions called "Risk-Modules", which each just look for suspicious factors in an email. <br/>
- After scanning, each email will get a risk-score as well as a breakdown of reasons *for* that score. <br/>
- Results are printed to screen and saved in a Results.json file, for later review.<br/><br/>
<img align="center" alt="program output" src="https://i.imgur.com/1YHQbcz.png">
<br>

---

<h2>Usage:</h2>


```
usage: SpamSpotter v 0.1 [-h] [-f Filename] [-d DirectoryToScan] [-V] [-vv] [-ai]

SpamSpotter is an email Threat-Hunting Tool. Given a list of emails, it will parse each one and give it a potential-risk score and a human-readable risk-breakdown based on the findings of its individual risk-modules.

options:
  -h, --help          show this help message and exit
  -f Filename         Choose a single file to examine.
  -d DirectoryToScan  Scan all email files in the provided directory (supports .eml and .msg files)
  -V                  Use VirusTotal for analysis (Requires API Key) ((I've included one of my own for the projects sake))
  -vv                 set verbose mode (extra debugging text)
  -ai                 Several AI will parse the email-body's content, and vote on wether each consider the message to be spam or not

2024 - By Chad Fry
```