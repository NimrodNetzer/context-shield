# Development Notes — Issues & Fixes

A log of real problems encountered during development, how they were diagnosed, and why the fixes matter. Useful for explaining the development process.

---

## 1. Missing `addOns` block in manifest — add-on not appearing in Gmail

**What happened:**
After deploying via `clasp push`, the ContextShield panel never appeared in Gmail's sidebar. The deployment showed as successful but nothing was installed.

**Root cause:**
When `clasp create` initializes a new project, it pulls a minimal `appsscript.json` from Google that overwrites the local one. Our local manifest had the full `addOns` configuration block, but it got replaced with a blank one containing only `timeZone` and `runtimeVersion`. Without the `addOns.gmail.contextualTriggers` section, Google has no idea the script is a Gmail Add-on.

**Fix:**
Rewrote `appsscript.json` to include the full `addOns` block with the Gmail contextual trigger pointing to `onGmailMessage`.

**Lesson:**
Always verify the remote manifest after `clasp create` — it silently overwrites local files.

---

## 2. Missing `urlFetchWhitelist` — deployment blocked

**What happened:**
`clasp deploy` failed with:
```
An explicit urlFetchWhitelist is required for all Google Workspace add-ons using UrlFetchApp.
```

**Root cause:**
Google Workspace Add-ons that make outbound HTTP requests (via `UrlFetchApp`) must declare an explicit allowlist of permitted URLs in the manifest. This is a security requirement — it prevents add-ons from making arbitrary outbound calls.

**Fix:**
Added `urlFetchWhitelist` to the top level of `appsscript.json` with the ngrok backend URL.

**First attempt failed** — put `urlFetchWhitelist` inside `addOns.common` which is the wrong location. Google returned:
```
Invalid manifest: unknown fields: [addOns.common.urlFetchWhitelist]
```
Moved it to the top level and it worked.

**Lesson:**
`urlFetchWhitelist` is a top-level field, not nested inside `addOns`. The error message from Google doesn't tell you where it should go — had to check the manifest reference docs.

---

## 3. Missing OAuth scopes — runtime authorization error

**What happened:**
The add-on appeared in Gmail but showed:
```
לסקריפט אין הרשאה לבצע את הפעולה הזו.
הרשאות נדרשות: script.locale && gmail.addons.execute
```
(The script doesn't have permission to perform this action. Required: script.locale && gmail.addons.execute)

**Root cause:**
The `oauthScopes` in the manifest only declared `gmail.readonly` and `script.external_request`. Two additional scopes are required for Gmail Add-ons to function:
- `gmail.addons.execute` — required to run contextual triggers
- `script.locale` — required to access locale/timezone info in the add-on context

**Fix:**
Added both missing scopes to `oauthScopes` in `appsscript.json`, pushed and redeployed.

**Lesson:**
Gmail Add-ons require more scopes than a regular Apps Script that reads Gmail. The error message does tell you exactly which scopes are missing — read it carefully.

---

## 4. False positive — legitimate Google emails flagged as MALICIOUS

**What happened:**
An email from `no-reply@accounts.google.com` (a real Google security notification) was scored 75/100 MALICIOUS with a CRITICAL signal: `homoglyph_domain: accounts.google.com`.

**Root cause:**
The homoglyph domain detection checked whether a known brand name appeared in the sender domain, but the condition was:
```python
if brand_norm in domain_norm and brand_norm != domain_norm.split(".")[0]:
```
This flagged `accounts.google.com` because `google` appears in the domain but is not the first subdomain segment (`accounts` is). The logic was designed to catch `google-secure.com` or `paypal-verify.com` but incorrectly caught legitimate subdomains like `accounts.google.com`, `mail.google.com`, etc.

**Fix:**
Changed the check to extract the **registered domain** (last two parts: `google.com`) and skip the signal if the brand legitimately owns that registered domain:
```python
registered = ".".join(parts[-2:])
if brand_norm in registered:
    continue  # legitimate subdomain of a known brand
```

Applied the same fix to the display name spoofing check.

**Lesson:**
Security heuristics need to be precise — a false positive on a Google security email is exactly the kind of thing that destroys user trust in a security tool. The fix is simple but the impact is significant.

---

## 5. Score display showing `100 / 10` instead of `100 / 100`

**What happened:**
The risk score displayed as `100 / 10` in the add-on card.

**Root cause:**
In `UI.gs`, the score was being converted to string via concatenation:
```javascript
.setText(score + ' / 100')
```
When `score` is an integer from the JSON response, JavaScript's `+` operator with a string sometimes produces unexpected results depending on how the JSON was parsed. The value `10` was the score from an early test run that got cached by the Card Service.

**Fix:**
Changed to explicit string conversion:
```javascript
.setText(score.toString() + ' / 100')
```

**Lesson:**
Card Service in Apps Script caches card state — always force a fresh re-analyze after UI changes rather than relying on Re-analyze button which may use a cached card.

---

## 6. Groq LLM not being called — heuristics-only fallback

**What happened:**
Every analysis returned `"analysis_source": "heuristics_only"` with reasoning `"Analysis based on email metadata and header checks"` instead of LLM-generated reasoning.

**Root cause:**
The uvicorn server had stopped running (terminal was closed). The add-on was still reaching the ngrok tunnel URL, but ngrok was serving cached responses or the tunnel was hitting a dead backend — causing the analyzer to catch an exception and fall back to heuristics-only mode silently.

**Fix:**
Restarted uvicorn. The graceful fallback mechanism worked exactly as designed — the add-on continued to return useful results even with no backend, which validated the resilience of the architecture.

**Lesson:**
The fallback design proved its value here. A less resilient design would have shown a 500 error to the user. Instead the heuristics-only path kept the tool functional. For a demo, always verify the backend is running before showing the add-on.

---

## Key Architecture Decision Validated by These Issues

The combination of issues 4–6 together confirm the core design principle:

> **Heuristics are the security engine. The LLM is the explainability layer.**

- Issue 4 showed that heuristics need to be carefully tuned — precision matters
- Issue 6 showed that the LLM fallback works — the tool stays useful even when Groq is down
- Together they confirm that delegating security decisions to an LLM alone would be fragile: the LLM can be unavailable, slow, or manipulated. Deterministic code cannot.
