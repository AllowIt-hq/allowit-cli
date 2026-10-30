# PaySH agent calls

`allowit paysh` serves operations recorded under an existing PaySH policy and its scoped capability. Do not deploy a separate PaySH policy or export a new capability for it. The backend journal keeps each original operation; recovery uses the same `POLICY`, `OPERATION_ID` and, for `call`, the identical `SERVICE_ID` and input. The agent sets `ALLOWIT_URL` and `ALLOWIT_PAYSH_TOKEN`; no signing key is read.

```sh
allowit paysh services
allowit paysh call POLICY OPERATION_ID SERVICE_ID '{"location":{"latitude":43.6532,"longitude":-79.3832},"universalAqi":true}'
allowit paysh status POLICY OPERATION_ID
```

## Requests

- `call` sends `POST /api/paysh/call` with `{policyId, operationId, serviceId, input}` and the capability as bearer.
- `status` sends `POST /api/paysh/status` with `{policyId, operationId}`.
- `services` sends `GET /api/paysh/catalog` without credentials and lists either the public catalog's `providers` or a cooperating backend's `{profile: "cooperating-v1", services}`. A cooperating price is shown as test-token units only on `solana:testnet`, never as USD or USDC, and a malformed list exits 3.

Each request is sent once with no redirect. `ALLOWIT_URL` must be an HTTPS origin, or HTTP on loopback. `INPUT_JSON` is limited to 4096 bytes and replies to 1 MiB. Payment and delivery are printed separately; `--json` adds `state` and `exitCode` to the server reply. The capability is redacted from all output.

## Exit codes

| Exit | Meaning |
|---|---|
| 0 | The API response was delivered. |
| 2 | Usage. |
| 3 | Configuration or authentication. |
| 5 | Unknown: network or server failure, redirect, unreadable or mismatched reply, HTTP 409, a `status` that finds no operation, operation status `unknown`/`settlement_unknown`, a failed, denied or expired operation with any receipt other than a swap, or an expired operation with a signature that has no receipt. The operation remains unresolved and payment may have been sent, neither failed nor delivered. |
| 12 | Pending: payment or delivery not complete. Includes `awaiting_input`, where the owner must answer in Allowit Requests, and `owner_approved`, a signed Yes for this original request only that establishes no payment. Keep the same `OPERATION_ID`. |
| 20 | Failed, denied or expired, with no delivery. `expired` means the answer-and-start deadline passed; it is not an owner denial. |

After exit 5, never use a new `OPERATION_ID` for the same call: run the printed `allowit paysh status` command or rerun the identical call.
