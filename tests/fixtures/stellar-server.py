"""Cooperating HTTPS/RPC fixture; deterministic test data, never a real payment."""
import base64
import http.server
import json
import pathlib
import ssl
import sys

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
        self.record({"kind": "paid" if credential else "quote", "path": self.path})
        if credential:
            if fixture.get("timeout"):
                self.connection.close()
                return
            decoded = json.loads(base64.b64decode(credential))
            if decoded != fixture["signed"]["payload"]:
                self.reply(400, {"error": "credential mismatch"})
                return
            self.reply(200, {"result": "cooperating-fixture"}, {"PAYMENT-RESPONSE": fixture["paymentResponse"]})
        else:
            encoded = base64.b64encode(json.dumps(fixture["paymentRequired"]).encode()).decode()
            self.reply(402, {}, {"PAYMENT-REQUIRED": encoded})

    def do_POST(self):
        fixture = json.loads((directory / "fixture.json").read_text())
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = request["method"]
        self.record({"kind": "rpc", "method": method})
        if method == "getNetwork":
            result = {"passphrase": "Test SDF Network ; September 2015"}
        elif method == "getLatestLedger":
            result = {"sequence": 3450}
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
