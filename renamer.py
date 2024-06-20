import os

for filename in os.listdir("."):
    if filename not in ["SpamSpotter.py", "renamer.py", "Entropy.py", "spam-words-EN.txt", "Results.txt", "__pychache__"] and ".eml" not in filename and ".msg" not in filename:
        os.rename(filename, filename+".eml")