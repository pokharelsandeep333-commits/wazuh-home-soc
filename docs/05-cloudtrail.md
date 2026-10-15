# 5. AWS CloudTrail

The agents see inside the servers. CloudTrail records the **AWS account itself**: console logins, IAM changes, security-group edits, instances launched, logging stopped. Someone with stolen AWS credentials never touches SSH, so without this the SOC is blind to account takeover.

```
AWS actions → CloudTrail trail → S3 bucket ← Wazuh manager aws-s3 module (every 10 min, read-only IAM user)
```

No agent and no Tailscale are involved: the manager pulls from S3 over HTTPS.

## Cost

The first copy of management events delivered to S3 by a trail is free; you pay only S3 storage (about 0.3 MB/day for my account). Don't enable data events, Insights, CloudWatch Logs delivery, SSE-KMS or a **second** trail: those are billed. If a trail already exists, reuse its bucket.

## Step 1: Trail and bucket

If you have no trail: CloudTrail → Create trail, management events (read + write), multi-region (the default; attackers launch miners in regions you never look at), **log file validation on**, SSE-S3 (not KMS), CloudWatch Logs off. In the bucket: all four Block Public Access settings on. Note the bucket name: `<CLOUDTRAIL_BUCKET>`.

## Step 2: Read-only IAM user, as code

```bash
aws cloudformation deploy --template-file aws/wazuh-cloudtrail-reader.yaml \
  --stack-name wazuh-cloudtrail-reader --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides TrailBucket=<CLOUDTRAIL_BUCKET>
```

[aws/wazuh-cloudtrail-reader.yaml](../aws/wazuh-cloudtrail-reader.yaml) creates user `wazuh-cloudtrail-reader` with no console access, `s3:ListBucket` on the bucket and `s3:GetObject` only on `AWSLogs/<your account ID>/*`. That's tighter than Wazuh's sample policy, which grants the whole bucket. Deleting the stack removes both cleanly.

The manager runs at home, not on EC2, so it can't use an instance role and needs an access key. Least privilege makes a leaked key nearly worthless. Rotate it about every 90 days.

## Step 3: Access key → credentials file

IAM → the user → Create access key ("Application running outside AWS") → **Download .csv**. Then, in a standalone PowerShell 7 window:

```powershell
pwsh -File scripts\manager\set-aws-credentials.ps1 -OutFile C:\wazuh\secrets\aws-credentials
```

It writes profile `[wazuh]`, locks the folder to your user, verifies the file, and deletes the `.csv`. On a Linux host, write the same file by hand with mode `600` in a `700` folder.

Why not paste the key: pasting into a hidden prompt delivered Ctrl+V as a single character in my console, and the AWS console's copy icon left the clipboard empty. The `.csv` route is deterministic.

## Step 4: Manager

1. Mount the file read-only into the manager (see [docker-compose-changes.yml](../wazuh/manager/docker-compose-changes.yml)): `<path>/aws-credentials:/root/.aws/credentials:ro`.
2. Add [wazuh/manager/ossec-aws-s3.xml](../wazuh/manager/ossec-aws-s3.xml) to `wazuh_manager.conf`. Set `<only_logs_after>` to the trail's first day to backfill; the default is today only.
3. `docker compose up -d --force-recreate --no-deps wazuh.manager`, then look for `Executing Bucket Analysis` and `Fetching logs finished` in the manager log.

The module tracks processed S3 objects, so a restart doesn't duplicate alerts. My backfill read 3 days in about 75 seconds and produced 41 alerts, including one **failed root login** I hadn't known about.

## Step 5: Rules and a live test

Deploy rules 100200-100207 ([04-detections.md](04-detections.md)). Then sign in to the console as root. Expect **100200** about 7 minutes later (CloudTrail delivery plus the 10-minute poll); allow up to 25 minutes before deciding it failed. Old logins from before the rule existed won't re-alert.

In the dashboard, CloudTrail alerts belong to **agent 000** (the manager), because no agent is involved. If an agent is pinned, the AWS card shows "No results". Alert timestamps are ingestion time; the real AWS time is `data.aws.eventTime`.

## Then stop using root

Create an admin IAM user with MFA in an `Administrators` group, and keep root (with MFA, no access keys) for break-glass only. After that, rule 100200 means "someone used the break-glass account". Creating that admin user is also a good live test of rules 100203-100205.
