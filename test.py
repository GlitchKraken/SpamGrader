import mailparser
import sys
import argparse

parser = argparse.ArgumentParser(
prog="SpamSpotter v 0.1",
description="SpamSpotter is an email Threat-Hunting Tool. Given a list of emails, it will parse each one and give it a potential-risk score and a human-readable risk-breakdown based on the findings of its individual risk-modules.",
epilog="2024 - By Chad Fry"
)
parser.add_argument("-f", help="Choose a single file to examine.", required=False, metavar="Filename")
parser.add_argument("-d", help="Scan all email files in the current directory (supports .eml and .msg files)", required=False, action="store_true")
parser.add_argument("-V", help="Use VirusTotal for analysis (Requires API Key) ((I've included one of my own for the projects sake))", required=False, action="store_true")
# below line of code basically just prints the help option if no args were supplied.
#Source: https://stackoverflow.com/questions/8259001/python-argparse-command-line-flags-without-arguments
args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])


# basic testing to make sure we can both check the argument provided, or wether a flag was ever set at all.
# note that was don't want file mode and directory mode to happen at the same time. 
# frankly, we should make sure everything works on a single file first.
if args.f == "blah":
    print("the file were gonna parse is called blah!")
elif args.d:
    print("Args D was supplied! entering ~DIRECTORY MODE~")





# consider writing parsing code where, by default, the program will print out the help-message...
# but there should be an option to judge a single-file... or every file in the directory with the script.




mail = mailparser.parse_from_file("personal/𝗬𝗢𝗨 𝗛𝗔𝗩𝗘 𝗕𝗘𝗘𝗡 𝗣𝗔𝗜𝗗💲𝘾𝙝𝙚𝙘𝙠 𝙮𝙤𝙪𝙧 𝙖𝙘𝙘𝙤𝙪𝙣𝙩 $7000.00💰.eml")

print(mail.from_  )

# below are the functions im kindly referring to as risk-modules. 
# these will be called on an email (or list of emails) to identify what stands out about the given email.
def riskVirusTotal():
    print("VirusTotal")
def riskKeyWords():
    print("KeyWords")
    
    
    

# project by Chad Fry, many thanks to the awesome
# team behind SpamScope! :D