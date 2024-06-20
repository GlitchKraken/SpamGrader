import os

for filename in os.listdir("."):
    if filename not in ["SpamSpotter.py", "renamer.py", "Entropy.py"]:
        os.rename(filename, filename+".eml")