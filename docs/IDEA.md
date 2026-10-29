# GitHub Profile Visitor Analytics --- Project Idea

## 1. Overview

**Working name:** ProfilePulse\
**Project type:** Public, reusable web service\
**Goal:** Let anyone add a small badge to their GitHub profile README to
display a visitor-related statistic, without hosting their own backend
or configuring a personal server.

Example README usage:

``` md
![Profile Views](https://YOUR-SERVICE.example/badge/GITHUB_USERNAME)
```

The intended experience is simple: add the badge, and the service
handles the counter and badge rendering.

## 2. The Problem

Many GitHub profiles display visitor badges, but these commonly count
requests to an externally hosted badge image---not necessarily actual
visits to the GitHub profile. The profile owner can increase the count
by refreshing their own page, and caching or proxying can affect which
requests reach the service.

GitHub's public API does not provide a documented endpoint that reports
every visit to a user's personal profile. Repository traffic analytics
are a separate feature and do not solve this problem.

## 3. Core Research Question

**Can a service embedded in a GitHub profile README reliably measure
visits to the actual profile page, rather than merely counting
badge-image requests?**

This is the first question to investigate. The project must not claim to
count actual profile visits unless experiments demonstrate that the
measurement is reliable.

## 4. Initial Prototype

Build the smallest experiment needed to understand the available
signals:

1.  Create an API endpoint that records a request and returns an SVG
    badge.
2.  Embed that badge in a test GitHub profile README.
3.  Compare direct endpoint requests with:
    -   opening the profile for the first time;
    -   refreshing the profile repeatedly;
    -   opening the profile in another browser or session;
    -   waiting and revisiting after a period of time.
4.  Inspect the effects of GitHub's image proxy and caching.
5.  Document what can and cannot be inferred from the resulting counts.

The experiment should distinguish **badge requests**, **estimated
visits**, and **verified profile visits**. These are not interchangeable
metrics.

## 5. Proposed Product --- If Measurement Is Feasible

-   A one-line Markdown badge for any GitHub user.
-   A centrally hosted counter service; users do not need to deploy
    their own server.
-   A simple, readable badge with customizable label and style.
-   Daily and cumulative counts only where the underlying data supports
    them.
-   Clear documentation explaining the metric and its limitations.
-   Basic abuse prevention, rate limiting, and service-health
    monitoring.
-   Minimal data collection, with no attempt to identify individual
    GitHub visitors.

## 6. Proposed Technical Architecture

The final stack should be chosen after the experiment. A possible
implementation is:

-   **API:** Python with FastAPI
-   **Storage:** PostgreSQL or another suitable persistent datastore
-   **Badge output:** Dynamically generated SVG
-   **Hosting:** A public cloud deployment
-   **Testing:** Automated endpoint tests plus manual browser
    experiments

A badge request might reach the API, update a counter, and return an
SVG. However, if GitHub serves a cached image or requests it through a
proxy, the service may not receive one request for every profile visit.
The architecture cannot fix a missing measurement signal by itself.

## 7. Constraints and Risks

-   **No documented personal-profile visitor API:** GitHub does not
    expose a public endpoint for all personal profile visits.
-   **Image proxying and caching:** GitHub may proxy or cache badge
    images, so badge requests may not map one-to-one to profile views.
-   **Repeated requests:** A counter may include refreshes, automated
    clients, or direct badge requests.
-   **Unique visitors:** IP addresses, cookies, and browser identifiers
    have limitations and privacy implications. The project should not
    promise unique-person counts without a defensible method.
-   **Abuse and reliability:** A public service needs rate limits, input
    validation, monitoring, and protection against inflated counts.
-   **Honest labeling:** If only badge requests can be measured, label
    the statistic accordingly---for example, "Badge Requests"---rather
    than "GitHub Profile Views."

## 8. Success Criteria

The prototype succeeds when it produces documented, repeatable evidence
about which events the service can observe and how caching affects the
count.

The public product should launch as an **actual profile visitor
counter** only if the experiment establishes a reliable method for
measuring actual profile visits. Otherwise, the project can still offer
a transparent badge-request counter, but it must not misrepresent that
metric.

## 9. Development Milestones

1.  **Feasibility test:** Build the endpoint and run the browser/profile
    experiments.
2.  **Evidence report:** Record observations, limitations, and
    repeatability.
3.  **Decision gate:** Decide whether actual profile visits can be
    measured reliably.
4.  **MVP:** Implement the supported metric, badge customization,
    persistence, and rate limiting.
5.  **Public release:** Publish documentation, deployment instructions,
    privacy notes, and service status.

## 10. Guiding Principle

**Measure only what the system can actually observe. Never present badge
loads as verified profile visits.**

The project's value depends on truthful measurement, not on displaying a
large number.
