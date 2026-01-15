#!/bin/bash
set -ex
echo "Running dbt clean up command..."
ls -la /app
ls -la /app/secrets
 
cd /app/dbt
pwd

dbt deps
dbt clean 
dbt compile

cd /app

echo 'Executing container override commands now...'
exec "$@"
