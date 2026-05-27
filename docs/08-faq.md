# FAQ

---

### What's the difference between this and Anubis?

[Anubis](https://github.com/TecharoHQ/anubis) is a proof-of-work challenge gate. It makes clients solve a SHA-256 PoW before accessing your site. That's effective against naive scrapers and AI crawlers that don't bother solving challenges.

Anti-Scrapling goes further in two ways. First, it detects scrapers before serving a challenge at all, using TLS fingerprinting (JA3/JA4), HTTP/2 SETTINGS analysis, and IP reputation. A known scraper library gets a 403 without ever seeing the challenge page. Second, the JS challenge collects 40+ browser fingerprint signals specifically targeting the weaknesses in Scrapling, curl-impersonate, patchright, and camoufox. A scraper that solves the PoW but fails the fingerprint scoring still gets blocked.

The PoW mechanism in Anti-Scrapling is directly inspired by Anubis. If your threat model is primarily AI crawlers and you don't need TLS-layer detection, Anubis is simpler to deploy.

---

### How is this different from Cloudflare Turnstile?

Cloudflare Turnstile is a managed, invisible CAPTCHA service. It works well and has a large fingerprint database, but it has a few constraints:

- It requires routing traffic through Cloudflare's network.
- The detection logic is opaque. You can't inspect or tune the signals.
- It doesn't do TLS-layer fingerprinting (JA3/JA4) because Cloudflare terminates TLS at their edge.
- Scrapling has a built-in Turnstile auto-solver that clicks the widget at a randomized delay. Anti-Scrapling specifically detects this click pattern.

Anti-Scrapling is self-hosted, open-source, and tunable. You can see exactly which signals fired and why a request was blocked. The trade-off is that you operate it yourself.

---

### Will this break my legitimate users?

It shouldn't, but the answer depends on your policy configuration.

Real browsers pass the JS challenge in under a second, receive a pass-token cookie, and are not challenged again for 24 hours (configurable). The challenge is invisible to the user — they see a brief loading screen, not a CAPTCHA.

The most common sources of false positives are:

- **Mobile users on carrier networks** whose IP changes between requests, invalidating the pass-token. Fix: remove `ip` from `token.bind_to`.
- **Corporate proxy users** whose proxy IP is in a cloud ASN. Fix: set `datacenter_ip` weight to 0 or add an allow rule for the proxy's ASN.
- **Your own automation** (CI, monitoring). Fix: issue a long-lived pass-token for your automation scripts.

See [Operations](07-operations.md) for detailed debugging steps for each scenario.

---

### Can it run behind a CDN?

Yes, with one caveat: TLS-layer signals (JA3/JA4) require Anti-Scrapling to terminate TLS. If a CDN terminates TLS before the request reaches Anti-Scrapling, those signals are unavailable.

In that configuration, Anti-Scrapling falls back to HTTP-layer signals (header order, UA/CH consistency, BrowserForge quirks), IP reputation, and the JS challenge fingerprint. This is still effective against most scrapers.

If you need TLS fingerprinting behind a CDN, some CDNs (Cloudflare, Fastly) can forward the JA3/JA4 hash in a request header. Anti-Scrapling can be configured to read these headers instead of computing the fingerprint itself. This feature is planned for v0.2.

---

### Does it support WebSocket?

Yes. WebSocket connections pass through the proxy transparently after the initial HTTP upgrade handshake is evaluated. The detection pipeline runs on the HTTP upgrade request (which carries all the TLS and HTTP signals). If the upgrade is allowed, the WebSocket connection is proxied without further inspection.

Behavioral signals (mouse path, resource blocking) don't apply to WebSocket connections.

---

### How accurate is the fingerprint scoring?

The scoring is based on weighted signals, not a single binary classifier. Each signal has an independently calibrated weight based on how strongly it correlates with scraper behavior.

High-confidence signals (weight >= 60) like `ja3_known_scraper`, `runtime_error_stack_pw_signature`, and `nav_webdriver_set` are near-certain indicators of a scraper. A single one of these firing is enough to deny or challenge.

Lower-confidence signals (weight 5-30) like `no_referer` or `datacenter_ip` are weak indicators that contribute to the score but don't trigger action alone.

The default policy challenges at score >= 40 and denies at score >= 80. These thresholds were chosen to minimize false positives on real users while catching the vast majority of scrapers. You can tune them for your traffic profile.

There's no published false-positive or false-negative rate because it depends heavily on your traffic mix. The adversarial test suite in `tests/scrapling/` verifies that Scrapling at a specific commit is blocked. Real-world accuracy against novel scrapers will vary.

---

### What about false positives?

False positives (real users blocked or challenged) are the main operational concern. The default policy is tuned conservatively: it challenges rather than denies on ambiguous signals, and the challenge is fast and invisible.

To investigate a false positive:

1. Check the audit log for the request: `curl "http://localhost:9090/admin/audit?ip=<user-ip>"`.
2. Look at the `signals` map to see which signals fired.
3. Decide whether to tune the weight of the offending signal, add an allow rule, or adjust the challenge/deny thresholds.

The most actionable false-positive signals are `datacenter_ip` (for API clients) and `no_referer` (for direct navigation). Both have low default weights and can be set to 0 without significantly reducing detection accuracy.

---

### Is the JS challenge invisible?

The challenge page shows a brief loading screen while the PoW solves. At difficulty 4 (the default), this takes 200-500ms on a modern laptop. The user sees a spinner or loading message, not a CAPTCHA widget.

After the challenge is solved, the browser receives a pass-token cookie and is redirected to the original URL. Subsequent requests from the same browser skip the challenge entirely.

The challenge is not completely invisible in the sense that there's a brief redirect and loading delay on the first visit. It's invisible in the sense that the user doesn't need to click anything or solve a puzzle.

---

### Can I use this with a SPA?

Yes. The challenge flow works with single-page applications, but you need to handle the redirect correctly.

When a SPA makes an API request and gets a 302 to the challenge page, the browser follows the redirect and loads the challenge. After solving, the browser is redirected back to the original URL. If the SPA was making an XHR/fetch request, the redirect will fail because fetch doesn't follow cross-origin redirects to HTML pages by default.

The recommended approach for SPAs:

1. Protect the initial HTML page load with the challenge (the user gets the pass-token on first visit).
2. The pass-token cookie is sent automatically with all subsequent API requests.
3. API routes check `has_valid_token: true` and allow through.

If you need to handle the case where a token expires mid-session, the SDK returns a `CHALLENGE` verdict with a `challenge_url`. Your SPA can redirect the user to that URL and handle the return redirect.

---

### GDPR / privacy?

Anti-Scrapling processes the following data per request:

- IP address (for IP reputation lookup and token binding)
- User-Agent string
- TLS fingerprint hashes (JA3/JA4)
- HTTP headers
- JS fingerprint data (collected during the challenge: navigator properties, WebGL info, canvas/audio fingerprints)

This data is used solely for bot detection. It's not shared with third parties.

**Retention:** The in-memory cache holds decisions for 60 seconds (configurable). The audit log retains entries in memory; there's no persistent storage by default. If you ship logs to an external system, that system's retention policy applies.

**Legal basis:** Processing is necessary for the legitimate interest of protecting your service from automated abuse (GDPR Article 6(1)(f)).

**Recommendations:**

- Document Anti-Scrapling in your privacy policy as a bot detection measure.
- If you ship audit logs to a log aggregation system, apply appropriate retention limits.
- The JS fingerprint data collected during the challenge is not stored after the challenge is evaluated. It's used only to compute the score and issue the pass-token.
- IP addresses in pass-tokens are hashed before storage if you configure `token.bind_to` without `ip`. To avoid storing raw IPs in tokens at all, remove `ip` from `bind_to`.
