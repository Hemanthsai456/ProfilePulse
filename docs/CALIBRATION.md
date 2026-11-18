# Calibration: how accurate is the badge?

The badge is an estimate. This procedure measures how far it is from what happened, using
controlled visits from known devices. Run it once after deployment, and again after any change
to dedupe, trust-proxy, or label logic. Record the results in your own notes or the table below.

## Before you start

- The deployment has `PROFILEPULSE_TRUST_PROXY=true`. Check `/report/<you>`: `trust_proxy` must be `true`.
  If it is `false`, stop. Every visitor looks the same and the results mean nothing.
- Put the badge in a test profile README (or a private test repo) that you control.
- Note the IST time before each step. All timestamps in `hits` are also stored as `ts_ist`.
- Wait at least 61 seconds between scenarios that should count separately, so the burst window does not
  merge them.

## Scenarios

Fill in **Observed** from the SQL query below after each step.

| # | Scenario | Action | Expected new count | IST time | Observed |
|---|----------|--------|--------------------|----------|----------|
| 1 | Desktop, GitHub signed in | Open profile once | 1 | | |
| 2 | Same desktop | Refresh 3 times within 5 minutes | 0 | | |
| 3 | Same desktop | Open profile again 2 hours later | 0 | | |
| 4 | Same desktop, next day | Open profile after IST midnight | 0 (within 30 days) | | |
| 5 | Phone, GitHub app | Open profile | 1 | | |
| 6 | Phone browser, Wi-Fi then mobile data | Open profile on Wi-Fi, then again on mobile data | 1 more (known limit: IP change) | | |
| 7 | Logged-out private window | Open profile | 1 | | |
| 8 | Two devices | Open profile on two devices within 30 seconds | 1 total (burst collapse) | | |
| 9 | Editor | Edit README, click Preview, then save and view profile | Record what happens | | |
| 10 | Owner | Your own profile visits | Counted (documented, not excluded) | | |

Scenario 9 is the known double-count case. Record the real behavior, not the expectation.

## Read the results

Replace `<you>` with your GitHub username (lowercase) and set the time window around your test run:

```sql
SELECT ts_ist, client_type, via_camo, visitor_key, counted_unique,
       burst_collapsed, xff_count, ip_version
FROM hits
WHERE lower(username) = '<you>'
  AND ts >= EXTRACT(EPOCH FROM TIMESTAMPTZ '2026-11-18 09:00:00+05:30')
ORDER BY ts;
```

How to read it:

- `counted_unique = 1`: this load was counted as a new visitor.
- `burst_collapsed = 1`: this load was merged into a load from the last 60 seconds.
- Same `visitor_key` on two rows: the server saw one viewer. Different keys: it saw two.
- `ip_version` and `xff_count` show whether the viewer IP was usable. `xff_count = 0` on a Camo request
  means the viewer was not identified, and that load will be counted as the proxy address.

## Score it

- Matches: scenarios where Observed equals Expected.
- Misses: scenarios where it does not. Record which way (over- or under-counted) and the likely cause
  from `ip_version`, `xff_count`, and `visitor_key`.

Expected accuracy: scenarios 1, 2, 3, 4, 7, and 8 should match. Scenario 6 is a known limit that cannot
be fixed without accounts. Scenario 9 is the known double-count case.

Keep the results with the commit they were measured on. Numbers from an older version do not describe
the current one.
