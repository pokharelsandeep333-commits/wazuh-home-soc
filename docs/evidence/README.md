# Evidence

Screenshots from my live Wazuh dashboard. Server names, the browser address bar and the Wazuh API ID are blurred.

## CIS hardening on the web server (Oct 9 2026)

Before: **53%** (127 passed, 110 failed, 42 not applicable), scan finished 13:03.

![CIS score before hardening, 53%](cis-webserver-before-53.png)

After two hardening batches: **65%** (172 passed, 90 failed, 17 not applicable), scan finished 13:37. "Not applicable" dropped from 42 to 17 mostly because installing auditd made the audit checks applicable.

![CIS score after hardening, 65%](cis-webserver-after-65.png)

## Brute-force attack chain (Oct 9 2026)

Threat Hunting filtered on `rule.id:(5712 or 40112 or 40501)` for the web server: 4 alerts, 3 of them at level 12 or above.

![Threat Hunting showing the brute-force chain](threat-hunting-bruteforce-chain.png)

## Still to add

- [ ] AWS root console login alert (100200), from Threat Hunting → Events
- [ ] The brute-force chain in the Events tab (one row per rule, with times)
- [ ] Discord `#wazuh-alerts` with a 100212 alert
- [ ] Tailscale policy editor with the `tests` block
- [ ] `nmap -Pn -p 22` against both servers from outside the tailnet
- [ ] Walkthrough video (2-3 min): live brute-force test → dashboard → Discord
