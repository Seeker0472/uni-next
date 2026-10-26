# Recovery and cleanup

The process writes `/var/lib/univpn/network-state.json` after acquiring each owned network resource. The journal contains only resource identifiers: no password, token, or session ID.

On clean shutdown it removes active routes and VIP state, deletes narrowly matched old-VIP conntrack entries, removes policy rules and unreachable guards, deletes its owned TUN, and finally removes the journal.

On startup it acquires `/run/univpn/instance.lock`, reads the journal, verifies the TUN alias contains the journal's random ownership ID, and removes the exact recorded routes and rules. It refuses to delete a same-named interface with a different alias.

## Failure cases

- Exit code 25 means cleanup or network application was incomplete. Inspect the journal before restarting.
- A corrupted journal is not ignored. Repair it or remove only resources proven to belong to this client.
- SIGKILL can leave unreachable guards and rules. This fails closed for protected destinations. Restarting the service performs owned-resource recovery.
- Stopping the service removes its guards. NetBird management may still advertise the resources, so withdraw them in NetBird when the service will remain disabled.

Useful read-only diagnostics:

```console
ip -d link show univpn0
ip -4 rule show
ip -4 route show table 20000
cat /var/lib/univpn/network-state.json
univpn status --run-dir /run/univpn --json
```

Do not flush all policy rules, routes, nftables, or conntrack state. That can break NetBird and unrelated host traffic.
