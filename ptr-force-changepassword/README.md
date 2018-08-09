Disclaimer 
---
These instructions and associated PowerShell script are provided “as is”.  Every effort was made to adhere to PowerShell best practices.  Please keep in mind, this is a “Script” and not an “Application”.  As such, logging is limited to script actions and assumes underlying PowerShell, Windows Authentication and associated modules/methods are configured and functioning correctly.

Lastly, this script and document only covers Email related remediation and therefore should not be treated as an exhaustive solution.  Endpoint, Proxy, Firewall and a number of other tools can and should be used.
Problem Statement

- Primary:
Proofpoint Targeted Attack Protection (TAP) tracks and reports Domain User(s) who have previously “clicked” and were “allowed” to continue to a URL that has since been deemed malicious.  This is usually the result of URLs that have been “weaponized” post-delivery.  While “Click” alerts do not equal infection, Many organization force uses to change their password as a protective measure.

It is important to note that all future “clicks” on malicious URLs will be blocked and the message no longer poses a threat.  As a matter of hygiene and to prevent users from reporting messages already marked malicious, it is a good idea to remove these messages from the inbox with Threat Response Auto-Pull (TRAP)

- Secondary (optional-highest level of protection):
Proofpoint TAP tracks and Reports on Attachments with embedded URLs.  Because these URLs exist in Attachment, the URL links cannot be rewritten.  These URLs are also susceptible to “weaponization” post-delivery.  Because the URLs are not rewritten, Proofpoint cannot report if the Domain User as accessed the URL.  Due to the lack of visibility, some Organization may choose to force Domain recipients to change their password as well.

Because the malicious URLs have not been rewritten, these messages still pose a threat and need to be removed from the Domain Recipient’s Inbox.  Threat Response Auto-Pull (TRAP) is the fastest way to respond to these threats.

Project Objective
---
To leverage Targeted Attack Protection (TAP), Threat Response Auto-pull (TRAP) and Windows PowerShell to automate the removal of email threats for Domain Recipient mailboxes and force Domain Users who have been potentially exposed to malicious content to change their password at next logon.

Solution Summary
---
Targeted Attack Protection (TAP) provides alerting and tracking of User Mailbox threats.  TAP support authenticated API access to alert, campaign and forensic detail.

Proofpoint Threat Response (PTR) Auto-Pull (TRAP) leverages the TAP APIs to manage alerts and provides many options for remediation.  In addition to extensive built-in functionality (e.g. TRAP), PTR also provides a REST API.

For this use case we will only be discussing Auto-Pull and the PTR API.

Auto-Pull will be used to move malicious Emails from Recipients’ mailboxes to a quarantine in a secured mailbox.  PTR quarantines the original email, any forwarded emails and all email of Distribution List members.

Additional details regarding TRAP installation and configuration can be found in the Threat Response portal, which is accessible directly from the PTR console, or via the link below:
	https://ptr-docs.proofpoint.com/ptr-guides/ptr-about/ 

In addition to Auto-Pull, PTR can be configured to automatically add users to a “List”.  Members of a list can be retrieved via a secure REST API web GET request to the PTR server.  Members can also be deleted with a secure web DELETE request.  Additional detail regarding the PTR API can be access via the PTR Portal from a licensed PTR Console.

Windows Task Scheduler is used to execute a PowerShell script every n minutes.  This script uses a web GET request to retrieve all members of the configured list, validates the account against AD users and verifies the AD User meets requirements.  Validated AD Users will be forced to change their password at next logon.  A web DELETE request removes the user from the configured list.

Script log are stored in a configured path on the PowerShell hosting the Scheduled task.  Updates are also shown in the PTR Console.
