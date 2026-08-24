"""
NetSage AI - REST API & Web Dashboard Server
Runs an HTTP server with zero external dependencies.
"""

import http.server
import socketserver
import json
import os
import sys
import urllib.parse
from engine.hybrid_diagnoser import HybridDiagnoser

PORT = 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
DATA_DIR = os.path.join(BASE_DIR, "data")

diagnoser = HybridDiagnoser()

class NetSageHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/cases":
            self.send_json_response(diagnoser.cases)
        elif path == "/api/stats":
            self.send_json_response(diagnoser.get_stats())
        elif path.startswith("/data/"):
            # Serve data files like cases.json or cases.csv
            file_rel = path.replace("/data/", "")
            target_file = os.path.join(DATA_DIR, file_rel)
            if os.path.exists(target_file):
                self.send_response(200)
                if target_file.endswith(".json"):
                    self.send_header("Content-Type", "application/json")
                elif target_file.endswith(".csv"):
                    self.send_header("Content-Type", "text/csv")
                self.end_headers()
                with open(target_file, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "Data file not found")
        else:
            # Fallback to serving static frontend from web/
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_length).decode('utf-8')
        try:
            payload = json.loads(post_body) if post_body else {}
        except Exception:
            payload = {}

        if path == "/api/diagnose":
            case_id = payload.get("case_id")
            symptom = payload.get("symptom", "")
            topology = payload.get("topology", "")
            show_outputs = payload.get("show_outputs", "")
            result = diagnoser.diagnose_case(case_id, symptom, topology, show_outputs)
            self.send_json_response(result)

        elif path == "/api/review":
            case_id = payload.get("case_id")
            status = payload.get("status", "Accepted")
            reviewer = payload.get("reviewer", "Senior Engineer")
            notes = payload.get("notes", "")
            adjusted_fix = payload.get("adjusted_fix")
            result = diagnoser.submit_review(case_id, status, reviewer, notes, adjusted_fix)
            self.send_json_response(result)

        else:
            self.send_error(404, "Endpoint not found")

    def send_json_response(self, data, status_code=200):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode('utf-8'))

def run_server(port=PORT):
    print("=" * 65)
    print(" 🚀 NetSage AI - Network Troubleshooting Assistant Server")
    print("=" * 65)
    print(f" Web Dashboard : http://localhost:{port}")
    print(f" REST API      : http://localhost:{port}/api/cases")
    print(f" Analytics     : http://localhost:{port}/api/stats")
    print("=" * 65)
    print(" Press Ctrl+C to stop the server.\n")

    with socketserver.TCPServer(("", port), NetSageHTTPHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down NetSage AI server...")

if __name__ == "__main__":
    port_to_use = PORT
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port_to_use = int(sys.argv[1])
    run_server(port_to_use)
