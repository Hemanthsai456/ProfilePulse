# Feasibility Experiment Guide

This document outlines the experimental protocol to evaluate how GitHub's image proxy (Camo) affects visitor measurement, as described in `IDEA.md` and `IDEA_v2.md`.

---

## 1. Background

When a badge image is embedded in a GitHub profile README:
```markdown
![Profile Views](https://your-profilepulse-domain.com/badge/YOUR_USERNAME)
```
GitHub's frontend rewrites image URLs to point to its anonymizing image caching proxy:
`https://camo.githubusercontent.com/...`

The visitor's browser makes requests to GitHub Camo. In turn, GitHub Camo makes requests to the ProfilePulse server.

### What We Can and Cannot Observe:
1. **Direct IP addresses of visitors:** Usually replaced by GitHub's proxy egress IP.
2. **Visitor User-Agents:** Often replaced by `github-camo (...)`.
3. **Repeated page refreshes:** May be cached at GitHub's edge (304 Not Modified or served from cache).

---

## 2. Experimental Protocol

Run this experiment on a test GitHub account. Check `GET /report/<username>` after each step and record the metrics.

### Step 1: Direct Baseline
Open the badge URL directly in a browser (e.g. `https://your-domain.com/badge/<username>`).
- **Expected:** `badge_loads` = 1, `via_camo` = 0, `distinct_visitor_keys` = 1.

### Step 2: First Profile Load
Add the badge to your GitHub profile `README.md` and visit your profile page once in a standard browser.
- **Expected:** `badge_loads` increases, `via_camo` increments.

### Step 3: Refresh Resistance Test
Refresh your profile page 5 times consecutively.
- **Observe:** Does `badge_loads` increase by 5, or does GitHub serve the image from cache?
- Note the ratio between your browser reloads and `badge_loads`.

### Step 4: Multi-Device Test
Open your profile from:
1. A separate browser on desktop.
2. A mobile phone using cellular data (different public IP).
3. A private / incognito browser window.
- **Observe:** Does `distinct_visitor_keys` increase, or does it stay at 1?

### Step 5: External Visitor Test
Have a friend or colleague in another geographic location load your profile page.
- **Observe:** Check if `distinct_visitor_keys` increases or if the request comes from the same Camo proxy cluster.

### Step 6: Cache Expiration Test
Wait 2 to 4 hours without visiting. Visit the profile again.
- **Observe:** Check if a new conditional request (`If-None-Match` or `If-Modified-Since`) is recorded.

---

## 3. Decision Gate

Evaluate your `/report/<username>` numbers:

| Signal in `/report` | Meaning | Decision |
|---|---|---|
| `distinct_visitor_keys` stays ~1 across devices | Visitors are completely obscured behind Camo proxies. | Per-person uniqueness cannot be claimed. Use **Badge Loads** and **Active Windows**. |
| `distinct_visitor_keys` increases with devices | Proxy passes sufficient unique request entropy. | **Daily Uniques (est.)** is feasible, documented with proxy caveats. |
| `verified_profile_visits` | Stays `null`. | Never claim verified profile visits from an image badge. |

---

## 4. Guiding Principle

> **Measure only what the system can actually observe. Never present badge loads as verified profile visits.**

