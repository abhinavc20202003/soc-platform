"""Response playbooks: containment steps and investigation checklists per alert type.
Kept as data so analysts can tune them without touching code."""

PLAYBOOKS = {
    "Brute-force login attempts": {
        "classification": "Credential Access: Brute Force",
        "containment": [
            "Block the source IP at the firewall or host firewall.",
            "Temporarily lock or rate-limit the targeted account(s).",
            "Enable or verify account lockout and MFA on exposed services.",
        ],
        "checklist": [
            "Confirm the source IP and whether it is internal, external or a known scanner.",
            "Review all events from this IP before and after the burst.",
            "Check whether any login from this IP succeeded.",
            "Check other hosts for the same source IP.",
            "Document findings and decide on blocking or escalation.",
        ],
    },
    "Multiple failed authentications on one account": {
        "classification": "Credential Access: Password Guessing",
        "containment": [
            "Contact the account owner to confirm whether they were locking themselves out.",
            "Force a password reset if the activity is not legitimate.",
            "Review the account's recent successful logins.",
        ],
        "checklist": [
            "Identify every source IP that targeted this account.",
            "Check whether the account is privileged.",
            "Look for a successful login after the failures.",
            "Verify lockout policy is working.",
        ],
    },
    "Failed logins followed by successful login": {
        "classification": "Initial Access: Valid Account Compromise (suspected)",
        "containment": [
            "Disable the account or terminate its active sessions immediately.",
            "Block the source IP at the firewall.",
            "Reset the account credentials and revoke keys and tokens.",
            "Isolate the host if post-login activity looks malicious.",
        ],
        "checklist": [
            "Confirm the successful login came from the same IP as the failures.",
            "Review everything the account did after the successful login.",
            "Check for privilege escalation, new accounts or persistence.",
            "Check for data access or exfiltration.",
            "Determine the scope: other hosts and accounts touched by this IP.",
            "Document timeline and root cause.",
        ],
    },
    "Activity from blocklisted IP": {
        "classification": "Threat Intelligence Match: Known Bad IP",
        "containment": [
            "Block the IP at the perimeter firewall.",
            "Review sessions currently open from the IP and terminate them.",
        ],
        "checklist": [
            "Confirm why the IP is on the blocklist and how recent the entry is.",
            "Review all activity from the IP across all sources.",
            "Check whether any authentication succeeded.",
            "Search for the IP on other hosts.",
        ],
    },
    "Credential guessing across many accounts": {
        "classification": "Credential Access: Password Spraying / Username Guessing",
        "containment": [
            "Block the source IP at the firewall.",
            "Check whether any of the targeted accounts now show a successful login.",
            "Enforce MFA on exposed services.",
        ],
        "checklist": [
            "List every account targeted and whether each exists.",
            "Check for any successful login from this IP.",
            "Review exposure of the targeted service (should it be internet-facing?).",
            "Look for the same IP against other hosts.",
        ],
    },
    "Privilege escalation indicator": {
        "classification": "Privilege Escalation: Elevated Access",
        "containment": [
            "Confirm with the user whether the privileged action was intended.",
            "If unexpected, suspend the account and terminate its sessions.",
            "Review sudo and administrator group membership for unauthorised changes.",
        ],
        "checklist": [
            "Identify exactly what command or action was run with elevated rights.",
            "Check whether sensitive files (for example /etc/shadow) were accessed.",
            "Verify the user normally performs privileged actions.",
            "Look for new accounts, scheduled tasks or services created afterwards.",
            "Document whether the activity was authorised.",
        ],
    },
    "Suspicious process execution": {
        "classification": "Execution: Suspicious Command or Tool",
        "containment": [
            "Isolate the endpoint from the network if the activity is not authorised.",
            "Terminate the suspicious process and preserve its details first.",
            "Collect the binary and command line for analysis.",
        ],
        "checklist": [
            "Identify the parent process and who launched it.",
            "Review the full command line.",
            "Check for network connections made by the process.",
            "Check for persistence (run keys, scheduled tasks, services).",
            "Decide whether this is an admin action, a test, or malicious.",
        ],
    },
}

DEFAULT_PLAYBOOK = {
    "classification": "Unclassified Security Alert",
    "containment": [
        "Review the evidence and decide whether containment is needed.",
        "Escalate to a senior analyst if the impact is unclear.",
    ],
    "checklist": [
        "Review the triggering events.",
        "Identify affected users and systems.",
        "Determine whether activity was authorised.",
        "Document findings.",
    ],
}


def get_playbook(alert_name: str) -> dict:
    return PLAYBOOKS.get(alert_name, DEFAULT_PLAYBOOK)
