"""Cooperating HTTPS/RPC fixture; deterministic test data, never a real payment."""
import base64
import http.server
import hashlib
import json
import os
import pathlib
import ssl
import subprocess
import sys
import time

directory = pathlib.Path(sys.argv[1])


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def record(self, value):
        with (directory / "requests.jsonl").open("a", encoding="utf-8") as out:
            out.write(json.dumps(value) + "\n")

    def reply(self, status, value, headers=None):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", "application/json")
        for key, item in (headers or {}).items():
            self.send_header(key, item)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        fixture = json.loads((directory / "fixture.json").read_text())
        credential = self.headers.get("PAYMENT-SIGNATURE")
        self.record({"kind": "paid" if credential else "quote", "path": self.path, "bearer": bool(self.headers.get("Authorization"))})
        if credential:
            if fixture.get("timeout"):
                self.connection.close()
                return
            decoded = json.loads(base64.b64decode(credential))
            if decoded != fixture["signed"]["payload"]:
                self.reply(400, {"error": "credential mismatch"})
                return
            receipt = fixture["paymentResponse"]
            if fixture.get("reflectCredential"):
                metadata = json.loads(base64.b64decode(receipt))
                metadata["untrustedDebug"] = credential
                receipt = base64.b64encode(json.dumps(metadata).encode()).decode()
            self.reply(200, {"result": "cooperating-fixture", **({"reflectedCredential": credential, "control": "\u001b[31m"} if fixture.get("reflectCredential") else {})}, {"PAYMENT-RESPONSE": receipt})
        else:
            encoded = base64.b64encode(json.dumps(fixture["paymentRequired"]).encode()).decode()
            self.reply(402, {}, {"PAYMENT-REQUIRED": encoded})

    def do_POST(self):
        fixture = json.loads((directory / "fixture.json").read_text())
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path.startswith("/api/stellar/"):
            self.record({"kind": "engine", "route": self.path, "credential": bool(self.headers.get("PAYMENT-SIGNATURE"))})
            if self.headers.get("Authorization") != "Bearer stellar-executor." + "a" * 32:
                self.reply(403, {})
                return
            policy = fixture["bundle"]["policy"]
            if request["policyId"] != policy["id"]:
                self.reply(403, {})
                return
            operation_file = directory / (request["requestId"] + "-engine.json")
            operation = json.loads(operation_file.read_text()) if operation_file.exists() else None
            result = {"requestId": request["requestId"], "policyId": policy["id"], "binding": {"config": fixture["config"], "policy": policy}, "operation": {"id": request["requestId"], "policyId": policy["id"], "method": "execute", "status": "prepared"}}
            if self.path.endswith("/execute"):
                if operation and operation["intent"] != request:
                    self.reply(409, {})
                    return
                decision = fixture.get("engineDecision", "allow")
                result["decision"] = decision
                if decision == "allow":
                    if operation and operation.get("approval"):
                        result["approval"] = operation["approval"]
                    else:
                        env = dict(os.environ, ALLOWIT_STELLAR_TEST_ENGINE_PREPARED=json.dumps(request["prepared"]), ALLOWIT_STELLAR_TEST_ENGINE_FIXTURE=str(directory / "fixture.json"))
                        output = subprocess.check_output([sys.argv[2], "--exact", "cooperating::engine_signer", "--nocapture"], env=env).decode()
                        approval = next(json.loads(line) for line in output.splitlines() if line.startswith("{"))
                        result["approval"] = approval
                    if fixture.get("engineBadApproval"):
                        result["approval"]["signature"] = "00" * 64
                operation = {"intent": request, "approval": result.get("approval"), "result": result}
                operation_file.write_text(json.dumps(operation))
                if fixture.get("engineDelay"):
                    time.sleep(fixture["engineDelay"])
            elif not operation:
                self.reply(404, {})
                return
            elif self.path.endswith("/report"):
                if request["signed"] != fixture["signed"]:
                    self.reply(400, {})
                    return
                result["proofAcknowledged"] = not fixture.get("engineBadAck", False)
                result["signedDigest"] = hashlib.sha256(json.dumps(request["signed"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                result["operation"]["status"] = "settled" if request.get("transactionHash") else "signed"
                if request.get("transactionHash"):
                    result["operation"]["transactionHash"] = request["transactionHash"]
                operation["result"] = result
                operation_file.write_text(json.dumps(operation))
                if fixture.get("engineDropReport"):
                    self.connection.close()
                    return
            elif self.path.endswith("/status"):
                result = operation["result"]
            elif self.path.endswith("/delivery"):
                result["deliveryAcknowledged"] = True
                result["operation"] = operation["result"]["operation"]
            else:
                self.reply(404, {})
                return
            if fixture.get("engineWrongBinding"):
                result["binding"]["policy"]["revision"] += 1
            self.reply(200, result)
            return
        method = request["method"]
        self.record({"kind": "rpc", "method": method})
        if method == "getNetwork":
            result = {"passphrase": "Test SDF Network ; September 2015"}
        elif method == "getLatestLedger":
            result = {"sequence": fixture.get("ledger", 3450)}
        elif method == "getLedgerEntries":
            result = {"entries": fixture["ledgerEntries"]}
        elif method == "simulateTransaction":
            if request["params"]["transaction"] == fixture["stateReadTransaction"]:
                result = {"results": [{"xdr": fixture["stateResultXdr"], "auth": []}]}
            else:
                result = {"results": [{"xdr": "AAAAAQ==", "auth": [fixture["authorizationXdr"]]}], "transactionData": fixture["transactionData"], "minResourceFee": fixture["minResourceFee"]}
            if fixture.get("restore"):
                result["restorePreamble"] = {"transactionData": fixture["transactionData"], "minResourceFee": "1"}
        elif method == "getTransaction":
            result = fixture["rpcTransaction"]
        else:
            self.reply(400, {"error": "unexpected RPC"})
            return
        self.reply(200, {"jsonrpc": "2.0", "id": request["id"], "result": result})


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(directory / "cert.pem", directory / "key.pem")
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_address[1], flush=True)
server.serve_forever()
