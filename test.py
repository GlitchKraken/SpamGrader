import mailparser
import sys
import argparse

parser = argparse.ArgumentParser(
prog="SpamSpotter v 0.1",
description="SpamSpotter is an email Threat-Hunting Tool. Given a list of emails, it will parse each one and give it a potential-risk score, based on the findings of its individual risk-modules.",
epilog="2024 - By Chad Fry"
)

parser.add_argument("-f", help="Choose a single file to examine.", required=False, metavar="Filename")
parser.add_argument("-d", help="Scan all email files in the current directory (supports .eml and .msg files)", required=False, action="store_true")


# below line of code basically just prints the help option if no args were supplied.
#Source: https://stackoverflow.com/questions/8259001/python-argparse-command-line-flags-without-arguments
args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])






if args.f == "blah":
    print("blah was blah")
if args.d:
    print("Args D was supplied! entering ~DIRECTORY MODE~")

# consider writing parsing code where, by default, the program will print out the help-message...
# but there should be an option to judge a single-file... or every file in the directory with the script.



# project by Chad Fry, many thanks to the awesome
# team behind SpamScope! :D


mail = mailparser.parse_from_file("personal/𝗬𝗢𝗨 𝗛𝗔𝗩𝗘 𝗕𝗘𝗘𝗡 𝗣𝗔𝗜𝗗💲𝘾𝙝𝙚𝙘𝙠 𝙮𝙤𝙪𝙧 𝙖𝙘𝙘𝙤𝙪𝙣𝙩 $7000.00💰.eml")

print(mail.from_  )
