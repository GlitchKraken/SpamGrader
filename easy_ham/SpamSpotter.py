import mailparser
import sys
import argparse
import json
import os
import vt
import hashlib
import math
import rich 

# Credit to the entire Entropy-Calculator goes to Ben Downing from red canary
#https://redcanary.com/blog/threat-detection/threat-hunting-entropy/
from Entropy import Entropy


emails = {}
    
email_score_breakdown = []

VirusTotal_Api_Key = "4617ea5bb1333b4dfecba3c69d2ec5daf19d53508e74321653b4dd8d36a07741"

VirusTotalFileURL = "https://www.virustotal.com/api/v3/files"
VirusTotalFileURL_Headers = {"accept": "application/json",
    "content-type": "multipart/form-data",
    "x-apikey": VirusTotal_Api_Key}

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
        riskEntropy(email)
        if args.V:
            riskVirusTotal(email)
        
        # all the modules have been run on the email, toss it in the dict and clear out the reasons list, for use in the next thingie.
        
        
        global email_score_breakdown
        
        # go through all of the risk ratings assigned to this email and total them...
        TotalScore = 0.0
        #
        for riskScoreBreakdown in email_score_breakdown:
            for test in riskScoreBreakdown:
                TotalScore += riskScoreBreakdown[test][0]
        
        
        #write results.
        TotalScoreList =  ["Total Risk Score:", TotalScore]
        email_score_breakdown = TotalScoreList + email_score_breakdown
        emails[args.f] = email_score_breakdown
        # done with calculations, reset the breakdown, and write the overall results to a file, JSON formatted.
        email_score_breakdown = []
        with open("Results.txt", "+w") as Results:
            Results.write(json.dumps(emails, indent=4))
        rich.print("\n\n\n"+json.dumps(emails, indent=4))
      
    elif args.f == "":
        print("Please provide an email to scan, or specify Directory Mode with -d")
    elif args.d:
        # this module is responsible for opening every .eml and .msg file in the current directory and
        # parsing them one-by-one. oh joy!
        print("=======================")
        print("Entering Directory Mode")
        print("=======================")
        emailList = []
        for files in os.listdir(os.getcwd()):
            if files.endswith(('msg', 'eml')):
                #print("file:")
                #print(files)
                emailList.append(files)
            else:
                continue
            
        for mail in emailList:
            print("Attempting to Analyze Email:        : " + str(mail))
            # basic error handling
            try:
                #try to create an entry in the emails dict, with the email itself 
                email = mailparser.parse_from_file(mail)
            except Exception as emailReadError:
                print("[-] Error while trying to open a given email file in Dir Mode: " + str(emailReadError))
                exit(0)
            
            
            
            # now run the email through each analysis module. maybe pass through a big dictionary where the email name/key has a list of values?
            riskKeyWords(email)
            riskEntropy(email)
            
            # all modules have been run on the email, add it do the big list.
            
            
            
            
            #emails[mail] = email_score_breakdown
            
            # go through all of the risk ratings assigned to this email and total them...
            TotalScore = 0
        
            for riskScoreBreakdown in email_score_breakdown:
                for test in riskScoreBreakdown:
                    print(type(riskScoreBreakdown[test][0]))
                    TotalScore += riskScoreBreakdown[test][0]
        
        
            #write results.
            TotalScoreList =  ["Total Risk Score:", TotalScore]
            email_score_breakdown = TotalScoreList + email_score_breakdown
            emails[mail] = email_score_breakdown
            
            email_score_breakdown = []
            
        # now, sort the results by the highest risk-score. Emails with a higher score should be shown first.
        #rich.print(json.dumps(emails, indent=4))
        
        for itemThing in emails.items():
            print(type(itemThing[1]))
        
        
        sortedEmails = dict(sorted(emails.items(), reverse=True, key=lambda item: item[1]))
        with open("Results.txt", "+w") as Results:
            Results.write(json.dumps(sortedEmails, indent=4))
            rich.print("\n\n\n"+json.dumps(sortedEmails, indent=4))
#############################################################################################################
# below are the functions im kindly referring to as risk-modules. 
# these will be called on an email (or list of emails) to identify what stands out about the given email.
# for now, they will be simple functions. later on we can start using more object-oriented approaches,
# or at least store them in an appropriate file.
#############################################################################################################

def riskKeyWords(email):
    # This module is in charge of checking for key-phrases in different parts of the email. 
    # it will function by checking the email for phrases commonly seen in spam.
    
    
    RiskScore = 0
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
            #print("Risky Phrase Found in email Body: " + phrase)
            RiskScore += 10
        if phrase in email.subject:
            #print("Risky Phrase Found in email Subject: " + phrase)
            RiskScore += 10
    
    # only append the score if something bad was found.
    if RiskScore > 0:
        global email_score_breakdown
        email_score_breakdown.append({"KeyPhrasesModule_Score": (RiskScore, Reasons_Bad)})
    #print(RiskPhrases)
    #print("Risk Score of Email: " + str(RiskScore))
    #print(email.name)
def riskVirusTotal(email):
    
    # NOTE: Deprecating this module almost immediately: 
    # it simply takes too long to query even a single file, and the free-api limit is quite low. 
    # a simple email-upload using the api was taking 5+ minutes. definitely not useful...
    # for testing purposes, and considering the low limit of the free API, manually 
    # uploading files for investigation makes more sense.
    
    # we can keep the functionality though, since we did put work into it...
    
    # first, check if the provided email even has attachments.
    print("VirusTotal")
    
    RiskScore = 0
    
    # Scan attachments and handle risk scoring for attachments.
    if len(email.attachments) >= 1:
        
        client = vt.Client(VirusTotal_Api_Key)
        
        print("attachments: " + str(len(email.attachments)))
        print(email.attachments)
        with open("./test5.eml", "w+") as test:
            md5_hash = hashlib.md5(test.read().encode()).hexdigest()
            # also worth noting that this step crashes a LOT... for a built-in API...
            analysis = client.scan_file(test, wait_for_completion=True)
            
            scannedFile = client.get_object("/files/"+str(md5_hash))
            
            print(scannedFile.last_analysis_stats)
            
            if scannedFile.last_analysis_status["malicious"] != 0 or scannedFile.last_analysis_status["suspicious"] != 0:
                # VT found something outright malicious. this represents a serious risk, lets indicate that accordingly.
                RiskScore += 100
            print("Risk Score: " + str(RiskScore))
            if RiskScore > 0:
                email_score_breakdown.append({"VirusTotalModule_Score: " : (RiskScore, "This email was given a higher score because VirusTotal marked it as Malicious in its results")})
            else: print("virus total found nothing wrong with the email")
            print(analysis.status)
            print(analysis.status)
            print(analysis.status)
            print(analysis.status)
        test.close()
        
    #Scan sender IP using VT and handle risk-scoring of IP...
    # orrrrr maybe not... we should be trying more interesting / new things anyway,
    # like Entropy-based detection and AI learning...
    
    # all VT processing is done, update risk score and reasons....
def riskEntropy(email):
    # The goal of this module will be to try and determine if a given field ()is 
    # first, lets check the entropy of the sender's name. a LOT of spam has nonsense usernames...
    #print("EntropyModule")
    
    
    RiskScore = 0
    
    fromAddr = ""
    # handle the number of from addresses the email has.
    # note that we care more about the domain than the user's chosen name
    
    
    
    if len(email.from_) > 0:
        #print("From: "+email.from_[0][1])
        # grab the domain instead of supplied name
        try:
            fromAddr = email.from_[0][1]
        except Exception as FromAddressError:
            print("[-] Error while trying to read from_address from current email:" + str(FromAddressError))
            fromAddr = ""
            return
        
        print("Emails From Addr: " + fromAddr)
        if fromAddr == "":
            print("EMAIL HAS NO FROM ADDR")
                    
        # Credit for snippet goes to
        #4.	https://redcanary.com/blog/threat-detection/threat-hunting-entropy/ ,
        Calculator = Entropy()
        
        FromAddrEntropy = 0.0
        # this could be a really good place to begin gathering data 
        # and doing evaluation.... like, what is the usual entropy of spam?
        # the usual entropy of ham?
        # are we doing to use this module more for the usage of finding blatantly-bad domains and marking them, or???
        FromAddrEntropy = Calculator.shannon_entropy(fromAddr)
        #print("Realtive Entropy for this email: "+ str(FromAddrEntropy))
        
        
        
        #something has gone horrible wrong here, but neither i nor god seem to know.
        if FromAddrEntropy > 3.8:
            # we will consider this random enough to be a "sus" domain and flag it with higher risk. 
            # since this domain is really random looking, we will consider it a significant risk, and give a bigger score.
            RiskScore += 100
            email_score_breakdown.append({"test": (100, "test2")})
            #email_score_breakdown.append({"EntropyModule_Score" : (RiskScore, "This email was given a higher risk-score because the sender's domain name looked suspiciously randomized, when compared to the alexa top 1 million.")})

    else:
        # no from address was supplied, supply non-severe error for module
        #print("From: "+ str(email.from_))
        #print("[!] Warning While running Risk Entropy: No From User or Domain was found!")
        fromAddr = "Error"
        return
    
if __name__ =="__main__":
    main()
    
# project by Chad Fry, many thanks to the awesome
# team behind SpamScope! :Dhttps://www.moxfield.com/decks/1Y5wngKTqkaxPREOX5yscg