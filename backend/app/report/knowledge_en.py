"""English versions of the deterministic reference texts (same keys as knowledge.py)."""

RULE_EXPLAIN = {
    "BF-001": "An adversary tries to guess the password of a specific account by testing many combinations in a short time. "
              "Each attempt produces a failed authentication event (4625/4771 or a “failed” outcome). The technique becomes "
              "critical if the streak ends in a successful logon.",
    "BF-002": "In password spraying the attacker tests a few common passwords against many accounts from the same source, "
              "to avoid per-account lockouts. The indicator is one IP with failures spread across many distinct users.",
    "BF-003": "A successful logon right after a streak of failures from the same source suggests the credential was "
              "guessed. It is the point where a brute-force attempt becomes possible valid access (T1078).",
    "LOG-001": "Successful access from external IPs geolocated outside the client's usual countries, or from IPs never seen "
               "for the account, is a classic indicator of stolen credentials used through remote services (VPN).",
    "LOG-002": "Interactive or remote logons outside the client's business hours may indicate illegitimate use of an "
               "account, although they are also common for on-call and remote work; they carry low weight unless correlated.",
    "LOG-003": "Service accounts are meant for automated processes (logon type 4/5). An interactive (2) or RDP (10) logon "
               "with a service account means someone is using its credentials manually.",
    "LOG-004": "Two successful logons of the same account from locations whose distance requires a physically impossible "
               "speed indicate that at least one of them is not the legitimate user (or that geolocation is inaccurate).",
    "LOG-005": "Concurrent sessions of one account from different external IPs suggest shared or stolen credentials.",
    "PE-001": "Adding an account to groups such as Administrators or Domain Admins grants full control over the machine or "
              "the domain. It is a typical step to consolidate access after compromising an account (T1098).",
    "PE-002": "Event 4672 records special privileges (SeDebug, SeTcb, SeImpersonate…) assigned at logon. Seeing it for an "
              "account that did not have them in the baseline indicates a privilege change.",
    "PE-003": "Creating or modifying accounts can be used to persist in the environment; in most cases it is routine "
              "administrative activity and must be checked against the onboarding process.",
    "PE-004": "Using alternate credentials (runas, sudo, 4648) lets processes run under another security context.",
    "EX-001": "PowerShell with -EncodedCommand and a hidden window is a common way to hide the executed script. The "
              "Base64 (UTF-16LE) content can be decoded to learn the real action.",
    "EX-002": "Legitimate system tools (certutil, bitsadmin, Invoke-WebRequest, curl) are abused to download attacker "
              "tools while evading controls (Ingress Tool Transfer, T1105).",
    "EX-003": "LOLBins are signed Windows binaries used to execute code by proxy (rundll32, regsvr32, mshta, WMIC), which "
              "makes allow-list detection harder.",
    "EX-004": "Running binaries from paths any user can write to (C:\\Users\\Public, %TEMP%) is characteristic of "
              "malicious payloads downloaded on the spot.",
    "EX-005": "Dumping LSASS memory (e.g. with comsvcs.dll MiniDump) or the NTDS database lets an attacker extract hashes "
              "and tickets of other accounts, enabling escalation and lateral movement (T1003).",
    "EX-006": "Disabling Defender real-time protection, the firewall or auditing reduces defensive visibility and usually "
              "precedes noisier actions (T1562.001).",
    "EX-007": "Clearing event logs (wevtutil cl, event 1102) aims to remove traces; later local telemetry may be "
              "incomplete (T1070.001).",
    "EX-008": "Scheduled tasks, new services or Run keys let the attacker regain execution after reboots or logoffs "
              "(persistence).",
    "EX-009": "Compressing data with a password and uploading it with curl or other utilities to external domains is a "
              "data collection and exfiltration pattern (T1560, T1048).",
    "LM-001": "One account authenticating over the network or RDP to several hosts within minutes indicates the attacker "
              "moving inside the network with valid credentials (T1021).",
    "LM-002": "An RDP or network logon to a critical server in an account→host combination never seen in the baseline is "
              "an indicator of lateral movement or unusual access.",
    "LM-003": "PsExec (PSEXESVC service), WMIC /node and WinRM run commands on remote machines; they are admin tools "
              "frequently abused for lateral movement.",
    "LM-004": "Hidden administrative shares (ADMIN$, C$) allow copying and running binaries on remote machines over SMB.",
    "EX-010": "Discovery commands (net view, whoami, Get-LocalGroupMember, Get-SmbShare…) let the attacker learn accounts, "
              "privileged groups and shares before moving or stealing data (Discovery).",
    "EX-011": "Deleting shadow copies or backups prevents file recovery and is the typical step before ransomware "
              "encryption (T1490). It requires administrative privileges on the machine.",
    "C2-001": "A command interpreter (PowerShell, cmd, mshta…) connecting directly to a public IP usually indicates a tool "
              "download or a command-and-control channel; legitimate software rarely does this.",
    "WEB-001": "A web shell is a script uploaded to the web server that runs system commands through HTTP parameters "
               "(e.g. ?cmd=whoami). If shell processes are also launched by the application pool identity (IIS APPPOOL, "
               "www-data), execution was effective (T1190, T1505.003).",
    "COL-001": "Sequential access to many distinct files on a share within minutes is characteristic of data collection "
               "before exfiltration or encryption (T1039).",
    "EXF-001": "A host sending hundreds of MB to a single external destination in a short time is consistent with "
               "exfiltration; volume and repetition (upload sessions) strengthen the suspicion (T1048).",
    "AN-001": "Statistical spike in event volume compared with the same hour on other days. It is context, not proof of an incident.",
    "AN-002": "Entity (user, host or IP) first seen after the baseline period. It may be legitimate (new hires).",
    "AN-003": "Very rare event or process not covered by rules. Useful for manual review.",
}

TACTIC_IMPACT = {
    "credential_access": "Credential exposure: the attacker may obtain valid passwords or hashes and reuse them on other systems.",
    "initial_access": "Unauthorized access to the corporate network with a valid identity, hard to tell apart from the legitimate user.",
    "execution": "Arbitrary code execution on the client's machines, with the ability to install additional tools.",
    "persistence": "The attacker remains after reboots or password changes unless the mechanisms created are removed.",
    "privilege_escalation": "Administrative control over machines or the domain, enabling changes to any resource or account.",
    "defense_evasion": "Loss of visibility and protection (antivirus disabled, logs cleared), which limits the investigation.",
    "lateral_movement": "Spread to critical servers, widening the compromise to core data and services.",
    "command_and_control": "Communication with the attacker's external infrastructure to download tools or receive orders.",
    "exfiltration": "Possible leak of sensitive information (data compressed and sent to an external destination), with legal and reputational impact (e.g. GDPR).",
    "collection": "Collection of client information in preparation for extraction.",
    "discovery": "Knowledge of the environment (accounts, groups and shares) that makes the attacker's next steps easier.",
    "impact": "Availability risk: without recovery copies, a later encryption would prevent restoring the data.",
}

RULE_ACTIONS = {
    "BF-001": [("investigar", 2, "Check with the owner of account {users} whether they recognize the attempts and review the source {ips}."),
               ("contener", 2, "Block the source IP {ips} at the perimeter/VPN if it is external.")],
    "BF-002": [("contener", 1, "Block IP {ips} on the firewall/VPN and check whether other IPs in the same range repeat the pattern."),
               ("investigar", 2, "Check whether any of the targeted accounts later logged on successfully from that IP.")],
    "BF-003": [("contener", 1, "Reset the password of {users}, revoke active sessions/tokens and enforce MFA."),
               ("investigar", 1, "Rebuild all activity of {users} since the first successful access from {ips}.")],
    "LOG-001": [("contener", 1, "Close the active VPN sessions of {users} from {ips} and restrict VPN access by geolocation."),
                ("investigar", 2, "Confirm with the user whether they travelled or used a commercial VPN.")],
    "LOG-002": [("investigar", 3, "Confirm with {users} whether the off-hours activity was legitimate.")],
    "LOG-003": [("contener", 1, "Rotate the password of service account {users} and deny it interactive/RDP logon via GPO."),
                ("investigar", 2, "Identify who used the service account from {ips} and for what purpose.")],
    "LOG-004": [("investigar", 1, "Determine which of the accesses of {users} is legitimate and treat the other as a compromise.")],
    "LOG-005": [("contener", 1, "Invalidate all sessions of {users} and force re-authentication with MFA.")],
    "PE-001": [("contener", 1, "Remove {users} from the privileged groups they were added to without authorization."),
               ("investigar", 1, "Audit every action performed with elevated privileges by {users} on {hosts}.")],
    "PE-002": [("investigar", 2, "Review why {users} obtained special privileges on {hosts}.")],
    "PE-003": [("investigar", 3, "Validate account creations/changes against approved tickets.")],
    "PE-004": [("investigar", 2, "Review the use of alternate credentials on {hosts}.")],
    "EX-001": [("investigar", 1, "Decode and analyze the PowerShell command run on {hosts}; look for the downloaded script."),
               ("remediar", 2, "Enable Script Block Logging and Constrained Language mode for PowerShell.")],
    "EX-002": [("contener", 1, "Block the identified download domains/URLs on the proxy and DNS."),
               ("investigar", 1, "Retrieve and sandbox the files downloaded on {hosts}.")],
    "EX-003": [("remediar", 2, "Restrict LOLBins (rundll32, WMIC, mshta) with ASR/AppLocker rules.")],
    "EX-004": [("contener", 1, "Isolate {hosts} from the network (EDR) and preserve a forensic image before cleaning."),
               ("investigar", 1, "Search for the binaries' hashes across the fleet and in threat intelligence sources.")],
    "EX-005": [("contener", 1, "Consider every credential that had a session on {hosts} compromised: rotate them, including krbtgt if the DC was accessed."),
               ("remediar", 1, "Enable Credential Guard / LSA Protection (RunAsPPL) on workstations and servers.")],
    "EX-006": [("contener", 1, "Restore Defender protection and the firewall on {hosts} and verify from the central console."),
               ("remediar", 2, "Turn on Tamper Protection to prevent local changes to the Defender configuration.")],
    "EX-007": [("investigar", 1, "Recover the cleared logs of {hosts} from the SIEM/central forwarding."),
               ("remediar", 2, "Ensure real-time event forwarding and alert on event 1102.")],
    "EX-008": [("contener", 1, "Remove the scheduled tasks and services created by the attacker on {hosts}."),
               ("investigar", 2, "Inventory other persistence mechanisms (Run keys, WMI subscriptions) on the affected hosts.")],
    "EX-009": [("investigar", 1, "Determine what data was compressed and sent; assess notification duties (GDPR art. 33, 72 h)."),
               ("contener", 1, "Block the identified exfiltration domains.")],
    "LM-001": [("investigar", 1, "Review every host accessed by {users} ({hosts}) for additional activity.")],
    "LM-002": [("contener", 2, "Allow RDP to servers only from authorized jump hosts.")],
    "LM-003": [("contener", 1, "Block PsExec/remote WMI from workstations and remove the PSEXESVC service on {hosts}.")],
    "EX-010": [("investigar", 2, "Review what information the attacker obtained with the discovery commands on {hosts}.")],
    "EX-011": [("contener", 1, "Isolate {hosts} immediately: deleting shadow copies usually precedes encryption."),
               ("remediar", 1, "Verify that offline/immutable backups exist and test restoring them.")],
    "C2-001": [("contener", 1, "Block the destination IPs on the firewall/proxy and isolate {hosts}."),
               ("investigar", 1, "Identify what was downloaded or sent over the outbound connections from {hosts}.")],
    "WEB-001": [("contener", 1, "Remove the malicious script from {hosts}, block IP {ips} on the WAF and isolate the server."),
                ("investigar", 1, "Review how the file was uploaded (upload vulnerability) and which commands were run."),
                ("remediar", 1, "Fix the file upload vulnerability and prevent script execution in /uploads.")],
    "COL-001": [("investigar", 1, "Inventory the files accessed by {users} and assess their sensitivity."),
                ("contener", 2, "Temporarily restrict the permissions of {users} on the share.")],
    "EXF-001": [("contener", 1, "Block the transfer destination on the proxy and isolate {hosts}."),
                ("investigar", 1, "Determine which data left (size, time) and assess notification duties (GDPR / local data protection law).")],
    "LM-004": [("remediar", 2, "Limit ADMIN$/C$ access to dedicated administration accounts (tiering).")],
}

GENERAL_RECOMMENDATIONS = {
    "bruteforce": "Require MFA on VPN and exposed services; apply progressive lockout and password-spraying detection.",
    "suspicious_logon": "Apply conditional access by geolocation and device; forbid interactive logon for service accounts (use gMSA).",
    "privesc": "Implement a tiered administration model, PAM/JIT for privileged groups and alerts on changes to critical groups.",
    "execution": "Deploy EDR with ASR rules, log PowerShell (Script Block Logging) and limit LOLBins with AppLocker/WDAC.",
    "lateral": "Segment the network, restrict RDP/SMB/WinRM between workstations and servers and use LAPS for local passwords.",
    "collection": "Apply DLP and outbound-volume alerts, and audit mass access to sensitive shares.",
    "web": "Keep web applications patched, use a WAF and disable script execution in upload directories.",
    "anomaly": "Maintain per-user/host behavior baselines to reduce false positives in future investigations.",
}

GENERIC_RECOMMENDATIONS = [
    "Centralize and retain logs (Security, Sysmon, VPN) for at least 12 months, with real-time forwarding to avoid losses from local clearing.",
    "Synchronize time (NTP) and export timestamps with an explicit timezone to make correlation easier.",
    "Formalize an incident response procedure with roles, contacts and notification criteria (GDPR / NIS2).",
    "Run regular awareness exercises on phishing and password hygiene.",
]
