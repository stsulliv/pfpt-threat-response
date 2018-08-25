# pfpt-threat-response
Contains scripts to integrate PTR and extend functionality

Basic IOC powershell scripts
---
- get_newest_security_event_logs.ps1
- list_installed_drivers.ps1
- list_installed_software.ps1
- list_of_scheduled_tasks.ps1
- list_services_configured_on_host.ps1
- list_startup_programs.ps1

ptr-force-changepassword
---
Script monitors a Threat Response user list and forces users to change password at next Logon

ptr-remediate-o365-account-mod (updated)
---
Available Remediation(s):
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
