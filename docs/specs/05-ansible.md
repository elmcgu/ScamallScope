# 05 Ansible

## Input

Output of a playbook run with the `ansible.posix.json` stdout callback [R21, R22]. Best in
check mode [R23], so `changed` means "this host has drifted from the playbook":

```bash
ANSIBLE_STDOUT_CALLBACK=ansible.posix.json ansible-playbook site.yml --check \
  > collector/integrations/ansible.json
```

`enrich --ansible-mode check|apply` (default `check`) says which kind of run it was. The
callback output does not record it.

Fields used: `stats` (`{host: {ok, changed, failures, unreachable, skipped, rescued, ignored}}`)
and `plays[0].play.duration.start` as the run time.

## Matching

Inventory host name to instance with `hosts.Index`.

## Output per instance (`config_run`)

`ok`, `changed`, `failures`, `unreachable`, `mode`, `ran_at`.

## Findings

| Check | When | Severity | BP |
|---|---|---|---|
| `ansible-host-failed` | `failures` > 0 or `unreachable` > 0 | medium | REL08-BP05 |
| `ansible-drift` | mode `check` and `changed` > 0 | medium | REL08-BP05 |

In `apply` mode `changed` is expected and is not a finding. Hygiene rule HYG-CFG-001 (spec 08)
covers running instances that are not in the run.

## Tests

| ID | Given | Then |
|---|---|---|
| ANS-1 | Stats for 3 hosts | 3 `config_run` entries with counts |
| ANS-2 | Check mode, host changed 2 | Finding `ansible-drift` |
| ANS-3 | Apply mode, host changed 2 | No finding |
| ANS-4 | Host unreachable 1 | Finding `ansible-host-failed` |
| ANS-5 | Host not in snapshot | In `unmatched` |
| ANS-6 | File without `stats` | `ValueError` |
