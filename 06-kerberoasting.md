# Kerberoasting in an Active Directory Home Lab

This writeup covers Part 6 (Step 7) of the [Active Directory Home Lab guide on cybercertprep.com](https://cybercertprep.com/blog/active-directory-home-lab-windows-server) — turning a clean AD lab into a practice range by introducing, exploiting, and detecting a Kerberoasting vulnerability.

## Lab Setup

**VMs:** DC01 (Windows Server, domain controller), WS01 (Windows 11 client), Kali Linux (attack box), all on an isolated `VMnet8` virtual network.

**Networking basics used:**
- **Host-only mode** permits network operations with the Host OS only.
- **NAT mode** masks all VM network activity as if it came from the Host OS, while still allowing external access.
- **Bridged mode** gives the VM its own IP on the physical network (via DHCP if enabled), acting like another physical node.

**Ways a VM can arrive:**
- An installer ISO — build an empty VM and install the OS from scratch, like a physical PC.
- A ready-made appliance (OVA/OVF) — import and boot.
- A pre-built VM folder — e.g. Kali's VirtualBox (`.vbox`/`.vdi`) or VMware (`.vmx`/`.vmdk`) images, opened directly.

Kali was kept current with:
```bash
apt full-upgrade -y
```

### Keeping the domain client in sync
Whenever a new Group Policy is pushed, the client needs:
```powershell
gpupdate /force
gpresult /r
```
Worth checking: that `Authenticated Users` hasn't been stripped from permissions in a way that blocks the computer from reading the GPO at all.

### Secure channel
A **secure channel** is the trusted communication relationship between a domain-joined computer and its Domain Controller — the foundation that makes authentication and policy delivery work.

## Background: What Is Kerberoasting?

Kerberoasting exploits the Kerberos authentication protocol. An attacker steals Kerberos **service tickets** in order to recover the plaintext password of a network service account offline. Once cracked, that service account can be used to steal data, move laterally, or deploy malware.

`krbtgt` is the built-in Active Directory account that underlies the whole Kerberos trust model on a domain.

Kerberoasting specifically targets domain accounts that have a **Service Principal Name (SPN)** registered — because an SPN is what makes an account "askable" for a service ticket.

### Setting up the vulnerable account

```powershell
setspn -S MSSQLSvc/sql01.test.local:1433 TEST\svc_sql
```

(Port `1433` is the default TCP port for Microsoft SQL Server — chosen to make the SPN look like a legitimate SQL service account.)

To inspect the SPN graphically: enable **Advanced Features** in ADUC, then check the **Attribute Editor** tab on the user object.

### Verifying connectivity from Kali

```bash
nc -zv 192.168.10.10 88
```

| Part | Meaning |
|---|---|
| `nc` | Netcat, a network utility |
| `-z` | Zero-I/O mode: scan the port without sending application data |
| `-v` | Verbose: show details of the connection attempt |
| `192.168.10.10` | IP of the Domain Controller |
| `88` | Kerberos port |

```bash
nslookup -type=SRV _kerberos._tcp.test.local 192.168.10.10
```

```
_kerberos._tcp.test.local   service = 0 100 88 pdc19.test.local.
```

Translation: to reach Kerberos for `test.local`, contact `pdc19.test.local` on TCP port 88.

(`/etc/resolv.conf` is where DNS resolution is configured on the Kali box, to make sure it was pointing at the DC.)

## The Kerberos Ticket Chain

There are two distinct ticket types in Kerberos, and `krbtgt` is tied to one of them:

1. **Log in to the domain** → the DC issues a **TGT** (Ticket Granting Ticket), using `krbtgt`. This is your long-lived "pass."
2. **Request access to a specific service** → present the TGT and ask for a **service ticket** tied to that service's SPN.
3. That service ticket is what actually grants access to the service.

The critical detail: when the DC issues a service ticket for `MSSQLSvc/sql01.test.local:1433`, that ticket is encrypted with a key derived from the **service account's password** (`svc_sql`) — not the requesting user's password, and not the DC's key.

**This is the entire vulnerability in one sentence:** any authenticated domain user can request a service ticket for any SPN, and that ticket comes back encrypted with the service account's password-derived key — no admin privileges required to ask for it.

## Performing the Attack

### Attack steps
1. Get a wordlist of candidate passwords.
2. For each word:
   - Derive a candidate key from the guessed password, using the same key-derivation function Kerberos uses (RC4-HMAC or AES, depending on ticket encryption type).
   - Attempt to decrypt the captured ciphertext with that candidate key.
   - Check whether the result looks structurally valid — Kerberos tickets have a predictable internal structure (e.g. a timestamp), so a wrong key produces garbage while the right key produces something recognizable.

This is exactly what [Impacket's `GetUserSPNs`](https://github.com/fortra/impacket) + [hashcat](https://hashcat.net/hashcat/) automate.

### Requesting the ticket

```bash
impacket-GetUserSPNs test.local/alice -dc-ip 192.168.10.10 -request
```

**Troubleshooting hit:** the first attempt failed with:
```
KDC_ERR_ETYPE_NOSUPP (KDC has no support for encryption type)
```
Diagnosis: `impacket-GetUserSPNs` defaults to requesting a modern encryption type (AES) that `srv_sql`'s configured `msDS-SupportedEncryptionTypes` didn't support — the account had been deliberately set to RC4 only. Confirmed with:
```powershell
Get-ADUser srv_sql -Properties msDS-SupportedEncryptionTypes | Select-Object msDS-SupportedEncryptionTypes
```
which returned `4` — the bit flag for RC4_HMAC_MD5.

Once the request was made in a way compatible with RC4, it returned a usable hash in the form:
```
$krb5tgs$23$*srv_sql$TEST.LOCAL$test.local/srv_sql*$<ciphertext>
```
The `23` in the hash is the Kerberos **encryption type (etype)** for RC4-HMAC — already embedded in the hash string.

### Why the password isn't "in" the ticket

A common misconception worth noting: the ticket does **not** contain the password hash anywhere inside it. The password-derived key is only ever used *as the encryption key* — it encrypts known structured data (like a timestamp) into ciphertext. The key itself never travels in the ticket. That's precisely why offline cracking is possible: there's nothing to directly "compare" — you derive a key from each guess, decrypt, and check whether the output looks like valid Kerberos ticket structure.

For RC4-HMAC specifically, key derivation is simple: it's the **MD4 hash of the UTF-16LE–encoded password** — the same key used for NTLM.

### Cracking with hashcat

Identifying the right hashcat mode took a short detour through `hashcat -hh | grep -i kerberos`, cross-referencing etype (23, matching the hash) against ticket type (**TGS-REP**, since this was a service ticket request, as opposed to AS-REP/Pre-Auth which belong to the initial login exchange — TGS stands for **Ticket Granting Service**, the part of the KDC that issues service tickets, versus AS, the Authentication Service, which issues TGTs).

Mode **13100** corresponds to "Kerberos 5, etype 23, TGS-REP":

```bash
hashcat -m 13100 ticket-ciphertext.hash mywordlist.txt
```

**First run exhausted the wordlist with 0 recovered**, despite the correct password being present in the list. Root-caused through a debugging pass: checked `wc -l` and `wc -c` on the hash file (ruled out line-break corruption and truncation), and `cat -A` on both files to check for hidden characters (carriage returns, stray whitespace) from copy-pasting terminal output into files. The password was ultimately reset cleanly via:
```powershell
$pw = ConvertTo-SecureString "20018973*Mq" -AsPlainText -Force
Set-ADAccountPassword -Identity srv_sql -NewPassword $pw -Reset
```
A **fresh ticket** was then requested (since the old one was encrypted with the old key) and the subsequent hashcat run **cracked successfully**.

## Why the Vulnerability Exists — and the Fix

A weak password is easy to guess: once a candidate word decrypts the ciphertext into something recognizable, that word is very likely the real password. This isn't a flaw in Kerberos itself — it's a weak-credential problem on the service account.

Mitigations:
- **Strong/long passwords** on service accounts, making offline brute-forcing impractical.
- **AES instead of RC4** encryption, removing the weaker, more easily crackable ticket format.
- **Group Managed Service Accounts (gMSA)** — ideal fix. These get a random 120+ character password, rotated and managed automatically; nobody ever sets or even sees it.

## Detection

Kerberoasting leaves a trail in the Domain Controller's Security event log:

- **Event ID 4769** — "A Kerberos service ticket was requested." Logged for every normal service access, so the ID alone isn't suspicious.
- The actual indicator: **Ticket Encryption Type = `0x17`** (RC4) for a service account that is **not** `krbtgt` and **not** a computer account (`$`-suffixed), especially combined with a single user requesting tickets for several different SPNs in a short window — a sign of mass roasting rather than normal use.

**To enable the underlying audit policy** (if not already active):
1. Run `secpol.msc`
2. Navigate: **Security Settings → Advanced Audit Policy Configuration → System Audit Policies → Account Logon**
3. Confirm **"Audit Kerberos Service Ticket Operations"** has Success auditing enabled

(Note: this subcategory lives under **Account Logon**, not the more intuitively-named **Logon/Logoff** category — an easy place to look in the wrong spot.)

## Summary

| Step | Tool/Command |
|---|---|
| Register SPN | `setspn -S MSSQLSvc/sql01.test.local:1433 TEST\svc_sql` |
| Verify Kerberos reachable | `nc -zv <dc-ip> 88`, `nslookup -type=SRV _kerberos._tcp.<domain> <dc-ip>` |
| Request ticket | `impacket-GetUserSPNs <domain>/<user> -dc-ip <dc-ip> -request` |
| Identify hashcat mode | `hashcat -hh \| grep -i kerberos` → 13100 for etype 23 TGS-REP |
| Crack | `hashcat -m 13100 ticket-ciphertext.hash wordlist.txt` |
| Detect | Event ID 4769, Ticket Encryption Type `0x17`, non-`krbtgt`/non-`$` service account |

---
*Part of an ongoing Active Directory home lab, following [cybercertprep.com's AD Home Lab guide](https://cybercertprep.com/blog/active-directory-home-lab-windows-server).*
