# Incident Report: Suspicious Authentication Followed by Privilege Escalation

## Incident summary

Microsoft Sentinel generated a High-severity incident after detecting repeated failed authentication attempts followed by a successful logon and subsequent addition of the same Windows identity to the local Administrators group.

Analytics rule:

`Suspicious Authentication Followed by Privilege Escalation`

The activity was generated intentionally in a controlled lab environment for detection-engineering and incident-investigation testing.

Final classification:

`Benign Positive — authorized security testing`

## Affected asset

Host:

`win-blue-team-lab`

Lab account involved in the controlled simulation:

`soclab-user`

The final detection query is generic and is not hardcoded to this account.

The incident was enriched using Microsoft Sentinel Host entity mapping.

## Detection source

The detection used Windows Security Events collected through:

- Windows Security auditing;
- Azure Monitor Agent;
- Data Collection Rule;
- Log Analytics;
- Microsoft Sentinel.

Relevant events:

| Event ID | Purpose |
|---|---|
| `4625` | Failed authentication |
| `4624` | Successful authentication |
| `4732` | Member added to a security-enabled local group |
| `4720` | Account creation context |
| `4672` | Additional privileged-logon context |

Event ID `4720` was intentionally not required by the final analytics rule because account creation may occur outside the detection window.

## Observed activity

The controlled sequence was:

```text
Failed Logon
Failed Logon
Failed Logon
      |
      v
Successful Logon
      |
      v
Account added to Administrators
```

The test account generated multiple failed authentication attempts and later authenticated successfully.

After the successful authentication, the same account was added to the local Windows `Administrators` group.

## SID correlation

The strongest part of the detection is identity-level correlation.

The successful Event ID `4624` provides:

`TargetUserSid`

The Event ID `4732` group-membership change provides:

`MemberSid`

The detection verifies that these SID values match.

This prevents an authentication event from one user from being incorrectly correlated with a privilege change affecting another user.

## Temporal correlation

The rule also validates the expected chronological order:

```text
LastFailed < SuccessTime < PrivilegeTime
```

This requires:

1. failed authentication attempts;
2. a later successful authentication;
3. a later Administrators-group membership change.

## Detection logic

The final query no longer filters specifically for `soclab-user`.

Instead, it:

1. collects Event IDs `4624` and `4625`;
2. extracts the account name;
3. groups authentication activity by host and username;
4. requires at least three failed logons;
5. requires at least one successful logon;
6. verifies that failures occurred before the success;
7. collects Event ID `4732` changes to the Administrators group;
8. joins the authentication and privilege activity on the same host;
9. verifies that the successful-logon SID matches the SID added to Administrators;
10. verifies that the privilege change happened after the successful authentication.

The full current detection query is maintained in:

[`queries/identity-privilege-escalation.kql`](queries/identity-privilege-escalation.kql)

Keeping the KQL in a dedicated file prevents the incident report from becoming outdated when detection logic is tuned.

## Microsoft Sentinel analytics rule

Rule name:

`Suspicious Authentication Followed by Privilege Escalation`

Configuration:

| Setting | Value |
|---|---|
| Severity | High |
| Query frequency | 5 minutes |
| Lookup period | 30 minutes |
| Trigger | More than 0 results |
| Incident creation | Enabled |
| Alert grouping | Disabled |

## Entity mapping

The affected host was mapped using:

```text
Entity type: Host
Identifier: HostName
Value: Computer
```

This allowed `win-blue-team-lab` to appear directly in the Sentinel investigation.

## Automated incident triage

A Sentinel automation rule named:

`Identity-Privilege-Escalation`

was configured to run when the incident was created.

The automation rule:

- set the incident severity to High;
- added the tag `Identity-Privilege-Escalation`;
- created an analyst investigation task.

The task instructed the analyst to:

- review failed and successful authentication activity;
- validate the account SID;
- verify the Administrators-group modification;
- inspect related Windows Security Events;
- determine whether the activity was authorized;
- decide whether containment was required.

No destructive containment action was automated.

## MITRE ATT&CK mapping

### Credential Access

`T1110.001 — Brute Force: Password Guessing`

The controlled activity included repeated incorrect password attempts followed by successful authentication.

### Privilege Escalation

`T1098.007 — Account Manipulation: Additional Local or Domain Groups`

The authenticated account was added to the local Windows Administrators group.

## Investigation findings

The investigation confirmed that:

- multiple failed authentication attempts occurred;
- the same account later authenticated successfully;
- the successful authentication contained a valid Windows account SID;
- Event ID `4732` recorded a member being added to the local Administrators group;
- the `MemberSid` from the group change matched the SID from the successful logon;
- the failed logons occurred before the successful authentication;
- the privilege change occurred after the successful authentication;
- Microsoft Sentinel generated the expected High-severity incident;
- Host entity mapping worked correctly;
- the automation rule added the expected tag and investigation task.

## Analyst assessment

Repeated authentication failures followed by successful access and a later privilege increase would require investigation in a production environment.

SID correlation increases confidence compared with host-only correlation because it confirms that the identity that authenticated successfully was the same identity that later received administrative privileges.

However, the sequence alone does not prove malicious activity.

Additional investigation should include:

- source IP address;
- logon type;
- originating workstation;
- account history;
- endpoint process activity;
- privileged activity after authentication;
- network activity;
- EDR telemetry;
- whether the Administrators-group modification was approved.

## Final classification

**Classification:** Benign Positive

**Reason:** Authorized security testing intentionally generated the activity.

**Severity:** High

**Status:** Investigation completed

## Recommended response

For a similar production incident, an analyst should:

1. Review the failed authentication attempts and their source.
2. Validate the successful authentication and account SID.
3. Confirm that the same SID was added to the Administrators group.
4. Identify the account that performed the group membership change.
5. Review logon type and source workstation.
6. Investigate Event ID `4672` and other privileged activity.
7. Search for suspicious endpoint processes.
8. Review persistence and lateral-movement activity.
9. Determine whether the privilege change was approved.
10. Escalate to containment if compromise is confirmed.

If malicious activity is confirmed, possible response actions include:

- disabling or resetting the compromised account;
- removing unauthorized Administrators-group membership;
- terminating unauthorized sessions;
- isolating the endpoint when necessary;
- rotating affected credentials;
- investigating related systems;
- preserving relevant forensic evidence;
- continuing incident response and threat hunting.

## Detection limitations

The detection focuses on SID and temporal correlation, but additional production tuning would still be required.

Potential false positives include:

- users mistyping passwords before a legitimate successful logon;
- approved helpdesk password recovery;
- legitimate local administrator assignment;
- endpoint-management activity;
- approved administrative workflows.

Current limitations include:

- correlation is performed on the same host;
- three failed logons is a lab-specific threshold;
- source IP and workstation context are not part of the final correlation;
- approved administrative workflows are not automatically excluded.

Possible production improvements include:

- environment-specific authentication thresholds;
- source IP correlation;
- workstation correlation;
- approved administrator baselines;
- exclusions for service accounts and management systems;
- Entra ID sign-in context;
- Defender for Endpoint process telemetry;
- identity-risk enrichment;
- historical behavior baselines.

## What changed after testing

| Finding | Change |
|---|---|
| Initial detection was hardcoded to `soclab-user` | Removed username hardcode |
| Host-level event correlation could associate unrelated identities | Added SID correlation |
| Event presence alone did not prove sequence | Added temporal validation |
| Event ID `4720` could occur outside the detection window | Kept account creation as investigation context |
| Analysts needed endpoint context | Added Host entity mapping |
| Initial triage steps were repetitive | Added Sentinel automation task |

## Outcome

The final detection chain was:

```text
Failed Authentication Activity
        |
        v
Successful Authentication
        |
        v
SID Extraction
        |
        v
Administrators Group Change
        |
        v
SID Match
        |
        v
Temporal Validation
        |
        v
Sentinel Incident
        |
        v
Host Entity Enrichment
        |
        v
Automated Analyst Triage
```

The lab demonstrated account-level correlation between authentication activity and privilege escalation while keeping the final detection reusable across usernames.
