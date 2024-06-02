import mailparser
import sys
import argparse
import json
import os

emails = {}
    
email_score_breakdown = []


def main():
    # Parse and add Arguments....
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


    VirusTotal_Api_Key = "4617ea5bb1333b4dfecba3c69d2ec5daf19d53508e74321653b4dd8d36a07741"
    
    

    
    # will be used to track emails scanned, as well as their risk-scores and reasons.
    #email[0] should always be total risk-score then.
    #email[1...n] should each be a tuple, with risk-score and per-module reason
    # a dict will be used for keeping track of large numbers of emails. assuming they are all uniquely named.

    
    
    
    #######################################
    # Logic for Handling Arguments
    #######################################
    if args.V:
        # might be unnecessary, since we can just check later down the line?
        print("VirusTotal mode")
    if args.f:
        
        print("=======================================")
        print("Opening " + str(args.f) + " for analysis" )
        print("=======================================\n")
        
        
        # basic error handling
        try:
            # try to create an entry in the emails dict, with the email itself 
            email = mailparser.parse_from_file(args.f)
        except Exception as emailReadError:
            print("[-] Error while trying to open single given email file: " + str(emailReadError))
            exit(0)
        
        
        
        # now run the email through each analysis module. maybe pass through a big dictionary where the email name/key has a list of values?
        riskKeyWords(email)
        
        
        # all the modules have been run on the email, toss it in the dict and clear out the reasons list, for use in the next thingie.
        global email_score_breakdown
        emails[args.f] = email_score_breakdown
        email_score_breakdown = []
        with open("Results.txt", "+w") as Results:
            Results.write(json.dumps(emails))
        print("\n\n\n"+json.dumps(emails))
      
    elif args.f == "":
        print("Please provide an email to scan, or specify Directory Mode with -d")
    elif args.d:
        # this module is responsible for opening every .eml and .msg file in the current directory and
        # parsing them one-by-one. oh joy!
        print("Args D was supplied! entering ~DIRECTORY MODE~")
        emailList = []
        for files in os.listdir(os.getcwd()):
            if files.endswith(('msg', 'eml')):
                print("file:")
                print(files)
                emailList.append(files)
            else:
                continue
            
        #for mail in emailList:
            # basic error handling
         #   exit(0)
         #   try:
         #       # try to create an entry in the emails dict, with the email itself 
         #       email = mailparser.parse_from_file(mail)
         #   except Exception as emailReadError:
         #       print("[-] Error while trying to open a given email file: " + str(emailReadError))
         #       exit(0)
            
            
            
            # now run the email through each analysis module. maybe pass through a big dictionary where the email name/key has a list of values?
            #riskKeyWords(email)


#############################################################################################################
# below are the functions im kindly referring to as risk-modules. 
# these will be called on an email (or list of emails) to identify what stands out about the given email.
# for now, they will be simple functions. later on we can start using more object-oriented approaches...
#############################################################################################################
def riskVirusTotal():
    print("VirusTotal")
def riskKeyWords(email):
    # This module is in charge of checking for key-phrases in different parts of the email. 
    # it will function by checking the email for phrases commonly seen in spam.
    
    
    RiskScore = 0.0
    Reasons_Bad = "This email was given a higher risk-score because certain phrases/words were found in this email that are commonly found in spam."
    
    # note that before we compare anything to this list, we should remove punctuation and lowercase it.
    # https://github.com/OOPSpam/spam-words/blob/main/spam-words-EN.txt
    RiskPhrases = []
    with open("spam-words-EN.txt", "r")  as spamPhraseFile:
        RiskPhrases = spamPhraseFile.read().lower().splitlines()
    # adding in some phrases I could think of that definitely would be annoying and in spam emails...
    # made sure to include some common spam-emoji's I've seen before too...
    RiskPhrases += ["f r e e", "urgent notice", "act now", "final warning", "final notice" "XXX", "$$", "$", "$$$", "immediate", "someone tried to log into your account", "suspended", "action required", "singles", "\N{Money Bag}", "\N{warning sign}", "\N{Heavy Dollar Sign}", "\N{Money-Mouth Face}" ]
    
    for phrase in RiskPhrases:
        if phrase in email.body:
            print("Risky Phrase Found in email Body: " + phrase)
            RiskScore += 10
        if phrase in email.subject:
            print("Risky Phrase Found in email Subject: " + phrase)
            RiskScore += 10
    
    # only append the score if something bad was found.
    if RiskScore > 0:
        global email_score_breakdown
        email_score_breakdown.append({"KeyPhrasesModule": (RiskScore, Reasons_Bad)})
    
    print(RiskPhrases)
    print("Risk Score of Email: " + str(RiskScore))
    print(email.name)

    





if __name__ =="__main__":
    main()
    
# project by Chad Fry, many thanks to the awesome
# team behind SpamScope! :D