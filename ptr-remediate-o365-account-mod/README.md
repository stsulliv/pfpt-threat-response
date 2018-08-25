To simplify management and extend re-usability, functions have been broken down into external scripts.

remediate-o365-account.ps1

Problem Statement
---
The growing number of Cloud Accounts being compromised and the resultiong required remediation steps are creating a resource drain on Security Operations.

Problem Overview
---
There is a separation between security tools that identify compromised accounts and the tools available to remediate compromised accounts. Complete remediation requires a number of steps and can take a considerable amount of time and effort.
The disconnect often exists because security tools identify multiple accounts, remediation tools are designed around remediating a single account.

Project Objective
---
To leverage Targeted Attack Protection (TAP), Threat Response Auto-pull (TRAP) and Windows PowerShell to automate a comprehensive remediation plan.

Available Remediation(s)
---
- Force User to change password at next logon
- Change the Account password
- Enable Strong Password
- Enable Multi-Factor Authentication
- Disable external email forwarding rules
- Delete external forwarding rules
- Remove Delegates (see Security Gaps below)
- Disable Delegates (see Security Gaps below)
- Enable mailbox auditing
- Disconnect User from Azure
- (Coming Soon) Outlook Folder permissions remediation (see Security Gaps below)

Security Gaps
---
As more users begin to use Outlook Online as their primary Email client the way mailbox sharing is done has changed. In the past with Outlook you could "delegate" access to your mailbox. I have not been able to find the equivalent feature in Outlook Online. The method for sharing in Outlook online to at the Folder level.  The current function to remove Delegates does not remediate folder permissions.
