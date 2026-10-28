# Code:You Capstone Part II: SOC Detection Engineering for a Phishing Attack Chain

**Status:** Capstone Part II (SOC detection track)

By Jean

Part I of this capstone (Python Log Analyzer): https://github.com/JeanIJ/capstone-log-analyzer

## Description

For Part II of the Code:You Cybersecurity capstone, I stepped into the role of a
SOC analyst reviewing a phishing incident and designing detections to catch a
similar attack next time. I analyzed the Phishing Unfolding incident and pulled
out every indicator I could find from two public walkthroughs. Then I built three
detection rules and a full SOC report so an analyst could catch this same attack
chain next time.

## Technologies

- Written detection rules aimed at an email gateway, endpoint logs (PowerShell command line and Sysmon process creation), and DNS logs
- Indicator checks with Talos, URLScan.io, and CyberChef
- Course-provided threat intel feed of IP and SHA-256 indicators (`ioc_dataset.json`)
- MITRE ATT&CK references recorded in the report (T1566.001, T1087.002, T1039, T1048.003)

## Setup and usage

Nothing in this repository needs to be installed or run. Browse the documents in this order:

1. `soc_detection_report.md` — the full detection engineering report (main deliverable), including the attack breakdown, rules, SOC workflow, false positives, and gaps
2. `outline.txt` — the candidate detection points and the three rules that were kept
3. `indicator-notes.txt` — indicators extracted from the scenario
4. `ioc_dataset.json` — the course threat intel feed used in the detection design
5. `screenshots/` — Talos, URLScan.io, and CyberChef verification

## The Scenario

The scenario is TryHackMe's "Phishing Unfolding." A phishing email pretending to
be an invoice went to an employee at a company called TryHatMe. The ZIP attachment
hid a shortcut file disguised as a PDF. When the employee opened it, PowerShell ran
a hidden command and gave the attacker remote control of the machine. The attacker
then mapped the network with PowerView and copied financial files into a staging
folder. The stolen data went out in small encoded pieces inside DNS requests to an
attacker domain.

Because the TryHackMe scenario is premium-locked, I documented the attack using two
public walkthroughs and verified the indicators myself:

- RTeam walkthrough: https://rteam.kz/en/blog/post-20241226/
- Medium walkthrough: https://medium.com/@rubyalhumidi/thm-soc-simulator-phishing-unfolding-4d1eb10a980a

My own verification work (Talos, URLScan.io, CyberChef) is in the screenshots/ folder.

## Detection Rules

1. Lookalike domain email with attachment
2. LNK file launching PowerShell download
3. PowerShell spawning nslookup with long subdomains

The full logic, reasoning, and SOC workflow are in `soc_detection_report.md`.

## Files in This Project

| File | What it is |
|---|---|
| `soc_detection_report.md` | The full detection engineering report (main deliverable) |
| `outline.txt` | Candidate detection points and the three rules that were kept |
| `indicator-notes.txt` | Investigation notes — every indicator extracted from the scenario |
| `ioc_dataset.json` | Course-provided threat intel feed used in the detection design |
| `screenshots/` | Verification work (Talos, URLScan.io, CyberChef) |

## What I Learned

Talos and URLScan had zero data on the attacker's domains so reputation tools alone
would not have caught this attack. Decoding the DNS data myself in CyberChef was the
moment I actually saw the stolen ZIP file leaving the network. In Part I I coded
detections in Python and here I designed detections for a full attack chain from the
first email to the data going out.
