# ProfilePulse — Improved Idea (v2)

## What changed from v1
v1 asked whether real profile visits can be measured. v2 keeps that question but
adds a clear product answer for each possible outcome, so the project is useful
whichever way the experiment goes.

## Your requirement
"Count a visitor once per day, even if they never opened any repo."

**The catch:** a README badge is an image. When someone opens your profile, their
browser asks GitHub's image proxy (camo.githubusercontent.com) for it, and the
proxy asks our server. Our server sees GitHub's proxy, not the visitor. So a
per-person, per-day count cannot be taken for granted. The experiment must show
whether the service can tell visitors apart at all
(`distinct_visitor_keys` in `/report/{username}`).

## Metrics (never mix these)
| Metric | Meaning | Status |
|---|---|---|
| Badge Loads | every request that reached our server | always measurable |
| Daily Uniques (est.) | one count per visitor key per UTC day | only meaningful if the experiment shows visitors are distinguishable |
| Active Windows | one count per profile per time window (e.g. 30 min) that had any badge load | measurable; resists refresh spam; not people |
| Verified Profile Visits | real visits to the profile page | not measurable from a README; stays `null` |

## Decision gate
After the experiment (see README), look at `distinct_visitor_keys`:
- **Stays ~1 while you browse from several devices** -> visitors are hidden.
  Ship Badge Loads and Active Windows, honestly labelled. Do not ship "unique visitors".
- **Grows with devices** -> Daily Uniques (est.) can ship, with the limits documented.

## Product improvements
- Honest default labels on the badge itself ("Badge Loads", "Daily Uniques (est.)").
- Owner-refresh protection: optional `?ignore_owner=1` plus Active Windows dedupe.
- Public methodology page and a live `/report` for each user, which is the transparency
  that fake-count badges lack and your main selling point.
- Privacy: store only an HMAC of IP + user agent, rotate the secret regularly, delete raw
  rows after 30 days, keep aggregates.
- Abuse control: per-profile rate limit (done), plus per-IP limits at the edge and a
  global cap on how many new profiles can be created per hour.
- Reliability: Postgres instead of SQLite for production, a cached count so a badge
  render does not need a heavy query, and `/health` for uptime monitoring.

## Roadmap
1. Deploy the prototype publicly (HTTPS needed, GitHub proxies only secure images).
2. Run the experiment on a test profile; save the `/report` output as the evidence report.
3. Decision gate (above).
4. MVP: chosen metrics, Postgres, per-IP rate limit, docs page.
5. Public launch.
