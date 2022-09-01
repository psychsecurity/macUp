# macUp

A python based macOS system enumerator and credential finder. The script only accesses non-TCC protected files/directories. Therefore, running it will not generate any TCC prompts. The name of the script pays homage to the PowerUp PowerSploit script.

The script does the following:

* Check if App context has Full Disk Access (FDA)
* Check if EDR (Carbon Black or CrowdStrike) and JAMF is installed
* Check and print contents of files in user's /.ssh and /.aws folders
* Check Slack storage for secrets
* Print zsh_history
* Grab firefox cookies and dump to CSV file

## Usage

`python3 macUp.py`
