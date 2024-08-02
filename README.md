# Device Registration Connectivity Analyzer

Windows PowerShell script to analyze network connectivity from either Entra AD joined or Hybrid Entra AD joined devices to Entra. This is useful in determining if certain IPs are getting blocked while others are allowed through resulting in the troublesome intermittent device registration / authentication issues.

# Requirements

Administrative privileges during script execution. 

# Script Execution

Open a PowerShell Window as an Administrator and browse to the location where both scripts in this repository are saved and execute it like the example below:

.\DevRegConnectAnalyzer.ps1

The ServiceDevRegConAnalyzer.ps1 script will be called by this script to run under the SYSTEM context to provide connectivity details for the System account.

If closed ports are encounted, the script will log them to the screen as well as to the log file to easily provide you a list of IP addresses and the hostname they are associated with that were unreachable over port 443.

![image](https://github.com/user-attachments/assets/425ad6e1-a1de-4f47-8a34-a3d7abae2ae9)
