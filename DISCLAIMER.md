# ⚠️ Disclaimer & Liability Limitation

**Use at your own risk.** The code, workflows, and scripts provided in this repository (`n8n-outbound-dns-dmarc-rua-xml-report-parser`) are for educational and architectural demonstration purposes.

**No Liability:** The author and dhRobin Systems assume no responsibility or liability for any direct, indirect, incidental, or consequential damages resulting from the use, misuse, or deployment of these scripts and workflows.

**Email Authentication, DNS & Alerting Risks:** DMARC monitoring carries inherent risks. Misconfigured sender allowlists, incorrect thresholds, malformed or unusual reporter XML, or aggressive alert settings can classify legitimate senders as spoofing sources (or miss real spoofing), produce misleading health scores, flood alert channels, or exhaust webhook and API rate limits. Acting on this workflow's output, in particular tightening a published DMARC policy (`p=quarantine` / `p=reject`) or changing SPF/DKIM DNS records, can cause legitimate email to be rejected, quarantined, or lost. The workflow reads from your IMAP mailbox and **marks processed messages as read**; it posts report data to the dashboard and alert webhooks you configure. It does **not** modify DNS records, DMARC policies, or mailbox contents beyond the read flag. Classification relies on the receiving provider's own DMARC evaluation in each report; it is not a substitute for a manual review before you change policy.

**User Responsibility:** You are solely responsible for compliance with applicable laws, regulations, and contracts, including data-protection and privacy rules (such as GDPR, CCPA, and CASL) that may apply to IP addresses, email addresses, and domain data contained in DMARC reports, data-retention obligations for the dashboard and n8n execution logs you operate, and the terms of service of your mailbox provider, n8n, Slack or any other alerting tool, your dashboard platform, and any other provider you connect. You are also solely responsible for proper testing (`SANDBOX_MODE=true`) before connecting any scripts to production environments, live mailboxes, live dashboards, or live notification channels.

Full text: DISCLAIMER.md · Licensed under the MIT License.

## License

MIT © 2026 dhRobin Systems · Provided as-is, see the disclaimer.

---

### MIT License

Copyright (c) 2026 dhRobin Systems

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

Full text: DISCLAIMER.md · Licensed under the MIT License. License: MIT © 2026 dhRobin Systems · Provided as-is, see the disclaimer.
