# Review: the fuzzing campaign

The hardening pass's campaign: every fuzz target run for at least 24 hours, with no open
findings. CI fuzzes each target for a minute on every push, and nightly for an hour;
the campaign is the long run. Each night starts from the corpus the night before grew
(kept in the Actions cache), and a failing input is kept as a run artifact for 30 days.

## How it runs

`scripts/fuzz-campaign.sh HOURS LANES` runs every target for `HOURS` each, `LANES` at a
time, starting from the committed seeds and the corpus earlier runs grew. Logs go to
`fuzz/campaign/`, one per target, and `summary.txt` records how each ended. A crash stops
its target, and the input is in `fuzz/artifacts/<target>/`.

The campaign runs on the development VM (Ubuntu, x86_64, 10 cores), as a systemd unit,
with 24 hours per target and 10 lanes.

## Targets

| Target | What it checks |
|---|---|
| `envelope_parse` | Any bytes as an envelope: no panic, and a parsed envelope writes back the same |
| `policy_parse` | Any bytes as a policy: no panic, and a valid policy round-trips |
| `url_match` | URL parsing and matching against destinations |
| `address_classify` | Address classification, including addresses embedded in IPv6 |
| `form_inject`, `json_inject` | Injection into any form or JSON body |
| `response_seal_json`, `response_seal_form`, `response_seal_xml` | A declared field never comes back in plaintext |
| `pg_preamble` | A caller's first Postgres packet |
| `pg_auth_messages` | Any server messages during a login: no panic, and no cleartext password unless allowed |
| `proto_send_head` | Any bytes as a `SendHead`, checked as the service does |
| `jwt_claims` | Any bytes as a token whose claims a policy exposes: only the named claims come out, as a JSON object |

## Findings

| Found | Target | What | Fixed |
|---|---|---|---|
| CI smoke run | `response_seal_xml` | After a UTF-8 byte order mark, the XML reader's positions were three bytes short, so a sealed field's replacement could leave the end of a token in the response | `f6f21f6`: seal skips the mark itself, and refuses unless each replaced range is exactly an element's content |
| Campaign, first minutes | `response_seal_json` | With `arbitrary_precision`, an object whose first key is `$serde_json::private::Number` parses as a number, and seal writes keys sorted, so a body could change meaning on its way through | `5dc5969`: seal refuses any JSON body in which a string, escapes decoded, is that token |

Each finding's input is a seed, so every later run checks it again.

## Status

Running since 10 November, 05:45 CET. The run started after the second fix stopped when
the VM's host lost its network and rebooted; it restarted from the corpus that run had
grown. The 24 hours per target end around 12 November, 05:50 CET.
