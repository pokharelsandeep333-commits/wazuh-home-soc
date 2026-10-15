# Security

## Using this repo safely

- Every value in angle brackets (`<WAZUH_MANAGER_IP>`, `<CLOUDTRAIL_BUCKET>`, `<DISCORD_WEBHOOK_URL>` and so on) is a placeholder. Replace it on your own machines and never commit the real value back.
- Secrets in this setup live in exactly three places, all outside git: the Wazuh passwords in `docker-compose.yml` (Wazuh's Docker deployment requires them there), the Discord webhook in `wazuh_manager.conf`, and the CloudTrail reader's access key in a `600` credentials file. The scripts read them at runtime and never print them.
- Only attack systems you own. The attack simulation in [docs/04-detections.md](docs/04-detections.md) is meant for your own servers.
- The CIS hardening scripts change system configuration. Read them, run them on a test machine first, and keep a second SSH session open while you test SSH changes.

## Reporting a problem

If you find a secret, a private address or a security mistake in this repo, open a GitHub issue without including the sensitive value, or contact me through the link in the README. I'll fix it and rotate anything that leaked.
