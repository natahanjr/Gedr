import sqlite3
import subprocess
import os

password = "SuperSecret123"
API_KEY = "sk_live_abcdef1234567890abcdef"

conn = sqlite3.connect("app.db")
user = request.form["username"]
query = "SELECT * FROM users WHERE name = '%s'" % user
conn.execute(query)

cmd = "ping " + host
subprocess.run(cmd, shell=True)

data = eval(request.form["data"])
result = pickle.loads(request.form["blob"])

import hashlib
hash = hashlib.md5(password.encode()).hexdigest()

os.system("del /q " + filename)
