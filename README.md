# WineAunt

A working wine-review website in the **Test Project** repository, deliberately built with known security weaknesses for evaluating **Assure**.

Browse three fictional wines, search by name or grape, sign in, write a star-rated tasting note, and edit reviews. The interface uses warm cream, burgundy and gold with a responsive wine shelf.

## Run locally

Requires Node.js 24 or newer. No external packages or installation step are required.

```sh
node server.mjs
```

Open http://127.0.0.1:3000. The app binds only to the local machine. This is intentionally insecure test software: use fictional data and do not expose it to the public internet.

Demo accounts: `alice` / `alice123` and `bob` / `bob123`.

Data persists in `data/wineaunt.db`, which is excluded from Git. To reset the lab, stop the server, delete that file and start again.

## Verify the fixture

```sh
node --test
```

The tests use an isolated in-memory database. They verify core flows and demonstrate selected intentional flaws. Passing tests mean the vulnerable fixture behaves as designed, not that it is secure.

## Testing with Assure

Point source-code analysis at this repository. For runtime analysis, start the app locally and provide its address and demo accounts to a scanner that can reach the same machine. A cloud scanner cannot reach your machine's loopback address directly.

See [EXPECTED_FINDINGS.md](EXPECTED_FINDINGS.md) for the ground truth and suggested fixes. These are deliberately authored CWE examples, not claimed third-party CVEs. Findings depend on Assure's supported languages, rules and analysis modes; no Assure integration is configured yet.
