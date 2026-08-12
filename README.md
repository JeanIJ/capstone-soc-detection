# Capstone Part II: SOC Detection Engineering (Phishing Scenario)

**Code:You Cybersecurity Capstone Part II: SOC Detection Track**
By Jean

Part I of this capstone (Python Log Analyzer): https://github.com/JeanIJ/capstone-log-analyzer

---

## Overview

For Part II of my capstone, I stepped into the role of a SOC analyst reviewing a
phishing incident and designing detections to catch a similar attack next time.
I analyzed the Phishing Unfolding incident and pulled out every indicator I could
find from two public walkthroughs. Then I built three detection rules and a full
SOC report so an analyst could catch this same attack chain next time.

## The Scenario

The scenario is TryHackMe's "Phishing Unfolding." A phishing email pretending to
be an invoice went to an employee at a company called TryHatMe. The ZIP attachment
hid a shortcut file disguised as a PDF. When the employee opened it PowerShell ran
a hidden command and gave the attacker remote control of the machine. The attacker
then mapped the network with PowerView and copied financial files into a staging
folder. The stolen data went out in small encoded pieces inside DNS requests to an
attacker domain.

Because the TryHackMe scenario is premium-locked, I documented the attack using two
public walkthroughs and verified the indicators myself:

- RTeam walkthrough: https://rteam.kz/en/blog/post-20241226/
- Medium walkthrough: https://medium.com/@rubyalhumidi/thm-soc-simulator-phishing-unfolding-4d1eb10a980a

My own verification work (Talos, URLScan.io, CyberChef) is in the screenshots/ folder.

## My Detection Rules

1. Lookalike domain email with attachment
2. LNK file launching PowerShell download
3. PowerShell spawning nslookup with long subdomains

The full logic, reasoning, and SOC workflow are in soc_detection_report.md.

## Files in This Project

| File | What it is |
|---|---|
| `soc_detection_report.md` | The full detection engineering report (main deliverable) |
| `indicator-notes.txt` | My investigation notes - every indicator I extracted from the scenario |
| `ioc_dataset.json` | Course-provided threat intel feed I used in my detection design |
| `screenshots/` | My own verification work (Talos, URLScan, CyberChef) |

## What I Learned

Talos and URLScan had zero data on the attacker's domains so reputation tools alone
would not have caught this attack. Decoding the DNS data myself in CyberChef was the
moment I actually saw the stolen ZIP file leaving the network. In Part I I coded
detections in Python and here I designed detections for a full attack chain from the
first email to the data going out.
