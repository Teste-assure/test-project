# Known intentional weaknesses

All examples below apply only to this local WineAunt lab. Both the source comments and these notes disclose the weaknesses so results can be assessed against a known baseline.

| Finding | CWE | Location / reproduction | Corrective approach |
| --- | --- | --- | --- |
| SQL injection in authentication | CWE-89 | On `/login`, username `alice' --` with any password signs in as Alice. | Parameterized SQL and verified password hashes. |
| SQL injection in wine search | CWE-89 | Search for `' OR 1=1 --` to return every wine; the input ' AND ( triggers a SQL error. | Parameterized queries, including LIKE patterns. |
| Stored cross-site scripting | CWE-79 | Sign in and submit `<script>window.wineauntProof=true</script>` as a review. The detail page inserts the script unescaped. | Escape output; sanitize explicitly supported markup; add CSP as defense in depth. |
| Client-controlled authentication | CWE-565 | Set cookie `user_id=1` to impersonate Alice without a password. | Unpredictable server-side sessions with protected cookies. |
| Missing review ownership check | CWE-639 | Sign in as Bob and edit `/review/1/edit`, which belongs to Alice. | Verify resource ownership on every read/write. |
| Plaintext password storage | CWE-256 | The users table and seed data contain plaintext demo passwords. | Salted password hashes using a suitable password hashing algorithm. |
| Sensitive information in errors | CWE-209 | Search for ' AND (; the response exposes database errors and a stack trace. | Generic client errors and private structured logs. |
| Session cookie lacks HttpOnly | CWE-1004 | Inspect the `Set-Cookie` response after login. | HttpOnly cookies, with Secure when deployed over HTTPS. |

The app also lacks login throttling and explicit anti-CSRF tokens. SameSite=Lax provides some cross-site protection, so absent tokens alone should not be treated as proof of an exploitable cross-site POST.

`server.test.mjs` confirms login injection, raw stored script markup, forged identity, unauthorized editing, and error disclosure alongside normal app flows. Browser execution of the stored script is not covered by those HTTP tests.

No real credentials, customer data, external attack targets, or vulnerable third-party dependencies are required. Demo passwords are public fixture data. Do not automatically treat them as leaked live credentials.

