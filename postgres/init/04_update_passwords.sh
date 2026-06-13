#!/bin/bash
# 04_update_passwords.sh
set -e
python3 -c "
import subprocess, os
roles = {
    'auth_app': os.environ['AUTH_APP_PASSWORD'],
    'audit_writer': os.environ['AUDIT_WRITER_PASSWORD'],
    'audit_reader': os.environ['AUDIT_READER_PASSWORD'],
}
for role, pw in roles.items():
    sql = f\"ALTER ROLE {role} WITH PASSWORD '{pw.replace(chr(39), chr(39)+chr(39))}'\"
    subprocess.run(['psql', '-U', os.environ['POSTGRES_USER'], '-d', os.environ['POSTGRES_DB'], '-c', sql], check=True)
print('Passwords updated')
"
