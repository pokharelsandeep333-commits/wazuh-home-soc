# 1. Tailscale: the private network

The Wazuh manager runs at home and the servers run on AWS. Wazuh agents **push** logs to the manager, so the servers have to open a connection into a home network, and home routers drop every connection that starts on the internet. Tailscale solves that without opening a single port: every device connects outward to Tailscale's coordination server, then the devices talk to each other over WireGuard.

| Option | Why I didn't use it |
|---|---|
| Port forwarding on the home router | Exposes a home machine to the whole internet |
| Run Wazuh on AWS | $30-70/month for the 8 GB RAM Wazuh needs |
| Plain WireGuard | One side still needs an open UDP port, so the NAT problem comes back |
| Reverse SSH tunnels | Fragile, one per server, no access control |
| Twingate free plan | Servers starting connections need Service Accounts, which the free plan doesn't include |

Do this whole page **before** installing Wazuh.

## Step 1: Wazuh host

1. Create a tailnet at <https://login.tailscale.com> (the free Personal plan is enough) and install Tailscale on the machine that will run Wazuh.
2. **Windows host:** tray icon → Preferences → **Run unattended**. Without it, Tailscale disconnects at sign-out and after a reboot, and the agents lose their path. Set it from the tray menu; the CLI flag is unreliable on desktop Windows.
3. Admin console → Machines → this machine → **Disable key expiry**. An expired key on the SIEM host means silent data loss after 180 days.
4. Note its address: `tailscale ip -4`. This is `<WAZUH_MANAGER_IP>` everywhere in this repo.

## Step 2: Access policy, before adding any server

Admin console → Access controls → JSON editor. Paste [tailscale/policy.hujson](../tailscale/policy.hujson) with your values filled in. Replace Tailscale's default allow-all policy **before** a server joins, so there is never a moment when a server can reach your whole network.

What the policy enforces:

- **Deny by default.** Anything not granted is blocked.
- Tagged servers reach the Wazuh host on **TCP 1514 only**. Not 1515 (enrollment), not SSH, SMB, RDP or the dashboard.
- **Servers can't reach each other.** A hacked server can't move sideways. Each server's `tailscale status` doesn't even list the other.
- The `tests` block runs on every save. Tailscale refuses to save an edit that would open one of the denied paths.

Network tests check the policy, not whether a service is listening, and they don't test the separate `ssh` rules. Verify those with real logins (step 4).

## Step 3: Each server (Ubuntu)

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --advertise-tags=tag:server --accept-dns=false --hostname=<name>
```

- `tailscale up` prints a login URL. Open it while signed in to approve the machine. No key or secret is copied to the server.
- `--advertise-tags=tag:server` puts the server under the restricted rules. Tagged devices have no key expiry.
- `--accept-dns=false` keeps the server's DNS untouched. **Essential on a DNS server**: certbot, apt and the resolver itself need working DNS.
- No security group change is needed. Tailscale works outbound-only.

Verify from the server:

```bash
tailscale ping <WAZUH_MANAGER_IP>      # first pongs via DERP relay, then "via <ip>:41641" = direct
nc -zv -w 5 <WAZUH_MANAGER_IP> 22      # must TIME OUT: servers only reach TCP 1514
```

## Step 4: Close public SSH

Once private SSH works, remove port 22 from the servers' AWS security groups.

```bash
sudo tailscale set --ssh        # on each server: Tailscale SSH, login tied to your Tailscale identity
```

```powershell
ssh ubuntu@<SERVER_TAILSCALE_IP>   # from your own device; no .pem needed
```

If you see `tailnet policy does not permit you to SSH to this node`: the default SSH rule (`dst: autogroup:self`) does not cover tagged devices. The second `ssh` rule in the policy (your login → `tag:server` → `ubuntu`) fixes it. Reopening port 22 does not.

**Rollback** (from a working session): `sudo tailscale set --ssh=false` returns to normal key-based SSH over Tailscale. Never run `tailscale down` or `logout` from your only access path.

Then prove it from **outside** your tailnet (a phone hotspot works):

```bash
nmap -Pn -p 22 <SERVER_PUBLIC_IP>     # filtered = closed to the internet
```

## Optional: Taildrop

`tailscale file cp <file> <device>:` copies files between your own untagged devices. It doesn't work with tagged servers.

Sources: [grants](https://tailscale.com/kb/1324/grants), [policy syntax and tests](https://tailscale.com/kb/1337/policy-syntax), [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh), [run unattended](https://tailscale.com/docs/how-to/run-unattended).
