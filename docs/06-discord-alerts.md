# 6. Discord alerts

Alerts that only live in a dashboard get missed: on my first day a level-15 alert fired and nobody was told. Every alert at **level 10 or above** now posts to a private Discord channel, and each message points to the triage playbook.

## How it works without custom code

Wazuh has no Discord integration, but Discord exposes a **Slack-compatible endpoint**: append `/slack` to a webhook URL (Discord developer docs, "Execute Slack-Compatible Webhook"). So Wazuh's built-in `slack` integration works. Before relying on it I checked that `/var/ossec/integrations/slack.py` doesn't restrict the URL to `hooks.slack.com`.

## Setup

1. Discord: a private server, a `#wazuh-alerts` channel → Integrations → Webhooks → New Webhook → Copy Webhook URL.
2. Add [wazuh/manager/ossec-integration-discord.xml](../wazuh/manager/ossec-integration-discord.xml) to `wazuh_manager.conf`, or on Windows run [scripts/manager/set-discord-webhook.ps1](../scripts/manager/set-discord-webhook.ps1) so the URL never appears on screen or in a backup.
3. `docker compose up -d --force-recreate --no-deps wazuh.manager`. Look for `wazuh-integratord: INFO: Enabling integration for: 'slack'`.
4. Test: send six requests for `/.env?wazuh-discord-test=N` to one of your servers. Expect 100210 ×5, then **100212** (level 10) and a Discord message.
5. **Confirm the message in Discord itself.** Delete the file you pasted the URL into.

## The bug: Wazuh said "sent", Discord said 400

My first test looked fine in `integrations.log`, but the channel stayed empty. Integratord doesn't log the HTTP response. Running `slack.py` by hand in debug mode showed `Response [400]` with the body `{"attachments": ["0"]}`.

Removing one field at a time:

| Payload | Discord |
|---|---|
| Wazuh's full payload | 400 |
| Hex colour instead of `danger` | 400 |
| Without `ts` | **200** |
| `ts` as an integer, or `null` | 200 |

`slack.py` sets `ts` to the alert ID, a decimal **string** like `"1791572047.3878538"`. Slack accepts it; Discord's Slack-compatible endpoint rejects the whole message. `generate_msg()` applies `<options>` *after* setting `ts`, so `<options>{"ts": null}</options>` overrides it. No Wazuh code is patched, so the fix survives upgrades.

Two gotchas from debugging it:

- Integratord calls `slack.py <alert> <api_key> <hook_url> <options_file>`. The options file is the **4th** argument; passed anywhere else it's silently ignored.
- Lesson: confirm delivery at the destination, not at the sender.

## Choosing the level

Before picking 10, I counted alerts at level 10+ on a heavy testing day: 13. A normal day is my own root logins plus the occasional scanner. After the tuning in [04-detections.md](04-detections.md), it's about 0-2 pings a day.

## Notes

- Alert contents (IPs, usernames, paths) are stored by Discord, a third party. Fine for a home lab with a private server; think twice for anything else.
- If the webhook leaks: delete it in Discord, create a new one, replace it in the config.
