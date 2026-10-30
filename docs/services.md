# Service commands

`allowit call` uses the selected Allowit account. The backend owns service adapters,
connections, credentials and payment preparation.

```sh
export ALLOWIT_URL='https://allowit.example'
export ALLOWIT_ACCOUNT_TOKEN='issued-account-capability'
allowit call seller/resource --input '{"query":"example"}'
```

Get the account capability through the owner app. Keep it in the process environment.
The CLI does not accept capability tokens in arguments or URLs.
`--account NAME` selects an account covered by that capability.
Without `--max-payment`, the backend applies the account's owner-configured limit.
`--max-payment AMOUNT --currency USDC` can lower that limit.

## Policies and request recovery

An explicit policy uses its separate `ALLOWIT_TOKEN` capability:

```sh
allowit call seller/resource --input '{"query":"example"}' \
  --policy revision@contract
allowit call seller/resource --input '{"query":"example"}' \
  --policy revision@contract --sandbox
```

The selector identifies a policy revision and its contract. Production requires that
contract's actively deployed revision. Sandbox accepts an authenticated undeployed revision
without selecting another source. The backend checks the selected rail and exact RPC.
Supply `--rail RAIL` and `--rpc URL` together when selecting a specific binding.
Sandbox does not authorize a production RPC or a deployment outside the signed intent.

The CLI requests an exact quote, then submits its quote ID with the same operation ID.
Each HTTP request is sent once. A policy denial stops the operation.
The CLI never retries a denied policy request through direct account authority.

Use `--request-id ID` for an explicit operation identity. The printed recovery command
retains the account, policy, sandbox and RPC context:

```sh
allowit call status OPERATION_ID --account NAME
```

After an uncertain response, inspect that operation. Keep its original ID.
Settlement and resource delivery have separate states. Exit 12 includes pending delivery
after settlement. `--json` returns the complete Allowit response.

## HTTP tools and agents

HTTP commands normalize requests and send them to the Allowit backend:

```sh
allowit curl https://api.example/data -X POST \
  -H 'Content-Type: application/json' -d '{"query":"example"}'
allowit wget https://api.example/data -O result.json
allowit http POST https://api.example/data query=example
allowit fetch https://api.example/data --body-file request.json \
  --content-type application/json
```

Explicit text body files are bounded to 32 KiB. The backend controls service credentials
and payment headers. Requests and replies retain their normal HTTP metadata.

`allowit mcp` exposes service discovery, calls and operation status over standard input
and output. Its authority and policy context come from its process configuration.

`allowit claude` and `allowit codex` launch the installed native applications with that MCP
connection. They use subscription authentication. They preserve native model choices,
permissions, approval gates, standard streams and exit codes.
They do not change saved native settings.

Put Allowit flags before `--` and native arguments after it:

```sh
allowit --sandbox codex -- exec --sandbox read-only --model MODEL 'Inspect the project'
allowit --policy revision@contract claude -- --model MODEL 'Inspect the project'
```

The launchers reject API/provider overrides. Claude reserves the session `--settings`
option for subscription authentication. Native saved settings and ordinary model and
permission flags remain available. Unavailable subscription authentication stops launch.
Capability tokens stay in the scoped child environment, outside process arguments.

## Accounts, catalogs and seller resources

`whoami`, `account`, `setup`, `topup`, `send` and `subscriptions` use account authority.
The backend admits each typed operation under its issued scopes. Administrative actions
also retain operation IDs. A policy capability cannot administer an account.

```sh
allowit whoami
allowit account list
allowit send AMOUNT RECIPIENT --currency USDC --request-id transfer-001
allowit subscriptions list
allowit skills search QUERY
allowit skills show SELLER/RESOURCE
allowit install SOURCE
allowit catalog scaffold SELLER/RESOURCE OPENAPI_URL --output-dir registry
allowit catalog check
allowit catalog build --output-dir registry
```

Catalog retrieval and compilation run in the backend. The CLI writes returned files only
into the selected output directory. It rejects traversal paths and symlink escapes.
Existing files require explicit `--force`.

`server scaffold` creates local seller configuration. `server demo`, `gate api` and
`gate inference` serve a registered backend resource through a local HTTP listener:

```sh
allowit server scaffold allowit-server.json
allowit gate api --resource /api/providers/demo/weather --listen 127.0.0.1:4020
```

The resource must appear in the backend's public `sellerResources` configuration.
The local facade serves that exact resource at `/` and forwards the caller's query,
body and payment headers. It does not forward an owner capability.
The registered backend resource verifies and settles payments.
Subscription plan metadata comes from installed backend resources.

Run `allowit COMMAND --help` for each command's argument summary.
