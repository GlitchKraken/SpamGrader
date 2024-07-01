from spam_detector_ai.prediction.predict import VotingSpamDetector
import time


start_time = time.time()

Oracle = VotingSpamDetector()

message = "Congratulations! you have won 1 million dollerydoos!$$$ click here to win your super prize! spam! fuck! damn! give me money money money"
message2 = "2e98572304957230498570239457asldkjlkajsdlkjashflkjahsfmn,zxbv,zjbcv?!"
message3 = "ok, but now we will have to run more tests on calculus next week. do you think thats going to fly? personally, I think we're going to wind up in a world of hurt. We may even run out of money."
is_spam = Oracle.is_spam(message3)


print(is_spam)
print("\n\n=== Total Runtime:  " + str(time.time() - start_time) + " Seconds === " )
