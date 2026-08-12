# SOC Detection Report: Phishing Unfolding

## 1. Executive Summary

An employee named Michael Ascot received a phishing email that looked like an invoice from a business partner. The attachment was a ZIP file hiding a shortcut that pretended to be a PDF. When he opened it the attacker got remote control of his computer. The attacker then explored the company network and copied financial files. The stolen data was sent out slowly inside normal looking internet requests. This attack is severe because customer financial data left the company and nobody stopped it while it was happening.

## 2. Attack Breakdown

**Stage 1: Initial Access.** At 8:22 AM an email from john@hatmakereurope.xyz arrived (Ticket 1015). The domain is a lookalike of the real company domain tryhatme.com. The email carried a ZIP attachment called ImportantInvoice-February.zip. This maps to MITRE technique T1566.001 which is spear phishing with an attachment.

**Stage 2: User Interaction.** Michael opened the ZIP and double clicked a file called invoice.pdf.lnk. The double extension made it look like a PDF document. It was really a Windows shortcut. Sysmon Event ID 15 shows the file stream being created when it was opened.

**Stage 3: Payload Execution.** The shortcut ran a hidden PowerShell command. The command used IEX and DownloadString to pull a script called powercat.ps1 from raw.githubusercontent.com. Powercat then connected back to 2.tcp.ngrok.io on port 19282. At 8:31 AM the attacker had a reverse shell which means full remote control of Michael's machine.

**Stage 4: Post-Compromise.** At 8:32 AM the attacker ran PowerView.ps1 with commands like Get-NetDomain and Get-NetGroup to map the network (T1087.002). Then net.exe mounted the share \\FILESRV-01\SSF-FinancialRecords and robocopy copied two financial files to a staging folder (T1039). The files were packed into exfilt8me.zip and split into base64 chunks. From 8:35 AM the chunks went out one by one inside nslookup requests to haz4rdw4re.io (T1048.003).

## 3. Detection Opportunities

**A. Lookalike sender domain.** The email came from hatmakereurope.xyz which looks almost like tryhatme.com and it carried a ZIP. This matters because the lookalike domain is what made the victim trust the invoice. An email gateway would catch this by comparing sender domains to the company domain.

**B. ZIP hiding a .pdf.lnk file.** The file invoice.pdf.lnk uses a double extension so it looks like a PDF but it is really a shortcut. This matters because the trick is what got the victim to run the attacker's command. An email gateway can scan inside ZIP files for .lnk files.

**C. LNK launching PowerShell with a download command.** The shortcut started PowerShell with a hidden download command (IEX ... DownloadString ... powercat). This is the exact moment the attacker got the reverse shell. Endpoint logs would catch this through PowerShell command line logging and Sysmon Event ID 1.

**D. PowerView recon and file staging.** PowerShell ran PowerView commands and then net.exe mounted a share while robocopy copied files. This is the attacker exploring the network and gathering the files to steal. Endpoint logs show both the PowerView commands and the net.exe and robocopy processes.

**E. PowerShell spawning nslookup.** PowerShell started nslookup.exe again and again with long random subdomains of haz4rdw4re.io. This is how the stolen data left the company in small encoded pieces. DNS logs would catch the strange long queries.

## 4. Detection Rules

**Rule name:** Lookalike domain email with attachment
**IF:** an incoming email comes from a domain that is only one or two characters different from tryhatme.com and it has a ZIP attachment
**THEN:** alert with severity Medium
**Data source:** email gateway
**Example line:** sender="*@hatmakereurope.xyz" attachment="*.zip"

**Rule name:** LNK file launching PowerShell download
**IF:** a .lnk file starts powershell.exe and the command line contains DownloadString or IEX
**THEN:** alert with severity High
**Data source:** endpoint logs
**Example line:** process_name="powershell.exe" parent_process="explorer.exe" command_line="*DownloadString*"

**Rule name:** PowerShell spawning nslookup with long subdomains
**IF:** powershell.exe spawns nslookup.exe and the DNS queries contain unusually long or random looking subdomains
**THEN:** alert with severity Critical
**Data source:** DNS logs
**Example line:** process_name="nslookup.exe" parent_process="powershell.exe"

## 5. SOC Workflow

When the lookalike domain rule fires Tier 1 checks the sender on a reputation tool like Talos like I did in this project. If the domain is unknown or lookalike they quarantine the email. When the LNK rule fires Tier 1 pulls the command line from the endpoint logs and decodes anything suspicious in CyberChef. If it downloads a script they escalate to Tier 2 right away because that means compromise. When the nslookup rule fires Tier 1 checks the DNS logs and looks up the domain on URLScan. If the subdomains look random and long they escalate. Tier 2 then isolates the host and starts the incident response process.

## 6. False Positives

Ticket 1003 is the perfect example from this case. It was an IT maintenance email from Yani Zubair with a script called forceupdate.ps1. It looked evil because it ran PowerShell and collected system information. It was actually legitimate IT work. Each of my rules could trip on normal activity too. Rule A could fire on real partner companies with similar names. Rule C could fire when IT admins use PowerShell to download tools. Rule E could fire on software that does long DNS queries or on IT running nslookup for troubleshooting. To tune the rules I would allowlist known IT accounts and servers. I would also add thresholds so one single nslookup does not alert but fifty in a row does.

## 7. Detection Gaps

The reputation tools had nothing on these domains. Talos returned no results at all for haz4rdw4re.io. It found hatmakereurope.xyz but the reputation was Unknown. URLScan had zero records for the exfil domain. The JSON threat feed only contained ip and sha256 indicators and no domains. None of my hashes matched it either. So the feed and the reputation tools would not have caught this attack. My screenshots in the repo prove all of this.

## 8. Recommendations

Immediate actions are to block haz4rdw4re.io at the DNS level and block .lnk files in email attachments. Short term the company should turn on PowerShell script block logging and start monitoring DNS for long random subdomains. Long term they should train users to spot double extensions and lookalike domains. They should also look for better threat feeds that include domains.

## 9. Reflection

The hardest part was getting into the room and learning the tools. URLScan confused me because the search page and the scan page look the same. I learned that you should decode everything because attackers hide the real meaning inside encoded strings. I also learned that reputation tools fail on fresh domains. In Part I I coded detections. In this part I designed them for a real attack chain and that felt much closer to real SOC work.

## Sources

- RTeam walkthrough: https://rteam.kz/en/blog/post-20241226/
- Medium walkthrough: https://medium.com/@rubyalhumidi/thm-soc-simulator-phishing-unfolding-4d1eb10a980a

Tool verification on Talos, CyberChef and URLScan was performed by me. Screenshots are in the screenshots/ folder in this repo.
