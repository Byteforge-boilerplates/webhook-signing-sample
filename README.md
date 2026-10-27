## ⚠️ Evaluation & Preview Only
This repository contains a stripped-down preview of the boilerplate for evaluation purposes. 
Production use, commercial use, and redistribution are strictly prohibited under the project's [LICENSE](LICENSE).

👉 **[Click here to buy the full, production-ready commercial license](https://byteforge.whop.site/)**

# Webhook signing sample

A small, dependency-free example of signing and verifying webhooks with HMAC-SHA256 and a timestamp.

## What is here

- `webhook_signing.py`: `generate_secret`, `sign`, `verify`, and `delivery_headers`.
- `test_webhook_signing.py`: unit tests. Run them with `python3 -m unittest -v`.

## The scheme

The header is `X-Example-Signature: t=<unix>,v1=<hex>`, where `v1 = HMAC_SHA256(secret, "<t>.<raw body>")`.
Receivers reject timestamps more than 300 seconds from their clock. During a secret roll, deliveries are signed
with the new secret, and verification accepts any secret still in its overlap window.

## Important

`verify` does not remember signatures it has accepted. Deduplicate on the event id header in your receiver, so a
replayed message inside the tolerance window does nothing.

## Usage

```python
import time
import webhook_signing as ws

secret = ws.generate_secret()
body = b'{"type":"usage.updated"}'
headers = ws.delivery_headers(secret, event_id="evt_1", raw_body=body, timestamp=int(time.time()))

# On the receiving side:
assert ws.verify(headers[ws.SIGNATURE_HEADER], body, [secret])
```

Verify against the raw bytes you received, not a re-serialized JSON body.
