# Phishing Email Header Analysis

## Summary
Header-level analysis of a phishing email impersonating a Microsoft account security notification. The investigation cross-checks sender identity claims against authentication results (SPF/DKIM/DMARC) and routing metadata to establish the message as malicious, despite it displaying a legitimate-looking sender name.

**Method:** Manual header analysis (From/Reply-To/Return-Path comparison, SPF/DKIM/DMARC validation)

## Findings

### Sender Identity Mismatch
| Field | Value |
|---|---|
| From Address | `Microsoft account team <no-reply@access-accsecurity.com>` |
| Reply-To | `solutionteamrecognizd03@gmail.com` |
| Return-Path | `bounce@nonkfrgr.co.uk` |
| Received (originating) | `nonkfrgr.co.uk` (89.144.9.87) |

The **From**, **Reply-To**, and **Return-Path** all point to different, unrelated domains — none of which belong to Microsoft. This is a classic display-name spoofing pattern: the visible sender name ("Microsoft account team") is designed to be trusted at a glance, while the actual delivery infrastructure is entirely unrelated.

### Authentication Failures
| Check | Result |
|---|---|
| SPF | `none` — no SPF record published for the sending domain |
| DKIM | `none` — message not signed |
| DMARC | `permerror` — policy could not be validated due to misconfigured/broken DNS |

None of the three standard email authentication mechanisms passed. A DMARC `permerror` in particular indicates the sending domain's DNS setup is broken or absent — legitimate senders don't typically have this failure mode, since it usually reflects an attacker using disposable or improperly configured infrastructure rather than a real corporate mail system.

### Additional Indicators
- Subject line: *"Microsoft account unusual signin activity"* — uses a generic urgency-driven subject with **"signin" misspelled** ("singin"), a common low-effort tell in mass phishing campaigns.
- Message-ID format appeared consistent with legitimate Microsoft/Outlook infrastructure — a reminder that Message-ID alone is not a reliable authenticity signal, since it can be present and well-formed even in a spoofed message.

## Conclusion
The message shows strong, multi-signal evidence of phishing: failed authentication across all three checks (SPF/DKIM/DMARC), a sender identity that doesn't match its own routing metadata, and a spelling error in the subject line consistent with low-effort mass phishing. The combination of technical (auth failure) and social-engineering (urgency, spoofed brand name) indicators makes this a high-confidence phishing classification.

## Detection Recommendations
- **Anti-phishing policy (Defender for Office 365):** enable **user impersonation protection** and **domain impersonation protection** for high-value targets (executives, IT/helpdesk, and commonly spoofed brands like Microsoft) — this would catch the display-name spoofing pattern seen here directly, rather than relying on the recipient noticing the domain mismatch.
- **Anti-malware policy:** ensure attachment filtering and common malware-type blocking are enabled, since credential-phishing campaigns like this one often pair with malicious attachments in other waves from the same infrastructure.
- **Enforce DMARC** at the mail flow level for inbound mail failing SPF/DKIM/DMARC from domains impersonating known brands, quarantining or rejecting rather than just tagging.
- Flag mismatches between From/Reply-To/Return-Path domains as a standing detection rule rather than relying on manual review.
- User awareness training should specifically call out that a trusted-looking display name provides no guarantee of sender authenticity.
