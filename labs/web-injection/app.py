from flask import Flask, request
import subprocess
app = Flask(__name__)
@app.get('/')
def index():
    host = request.args.get('host', '127.0.0.1')
    # Intentional command injection for the lab.
    cmd = f"ping -c 1 {host}"
    out = subprocess.getoutput(cmd)
    return f"<h1>Red Injection</h1><p>Try ?host=127.0.0.1</p><pre>{out}</pre>"
app.run(host='0.0.0.0', port=8080)
