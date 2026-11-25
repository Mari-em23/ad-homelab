# Active Directory Home Lab

A hands-on home lab built to learn Active Directory administration, common attack techniques, and detection — from the ground up.

## Lab Environment

- **DC01** — Windows Server, Domain Controller for `test.local`
- **WS01** — Windows 11, domain-joined client
- **Kali Linux** — attacker/analysis box
- All VMs on an isolated `VMnet8` virtual network

Built following the [AD Home Lab guide on cybercertprep.com](https://cybercertprep.com/blog/active-directory-home-lab-windows-server), extended with additional practice exercises and writeups.

## Writeups

| # | Topic | Status |
|---|---|---|
| 06 | [Kerberoasting](./06-kerberoasting.md) | ✅ Complete |
| 07 | AS-REP Roasting | 🔜 In progress |
| 08 | Pass-the-Hash & LAPS | ⏳ Planned |

## What's Covered

Each writeup documents: how the vulnerability was set up, the attack performed step by step (including real errors hit and how they were debugged), why the attack works, how to fix it, and how to detect it in the Domain Controller's event logs.

## Tools Used

Impacket, hashcat, PowerShell, Active Directory Users and Computers, Group Policy Management, Event Viewer.

---
*Work in progress — new writeups added as the lab grows.*
