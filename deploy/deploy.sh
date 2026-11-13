#!/bin/bash
# Simple manual deployment script (if not using GitHub Actions)
set -euo pipefail

cd /home/hvt/hvt
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate --noinput
python manage.py collectstatic --noinput

echo "Gracefully reloading Gunicorn and restarting Worker..."
if [ -f /tmp/hvt-gunicorn.pid ]; then
    kill -HUP $(cat /tmp/hvt-gunicorn.pid)
fi
if systemctl is-active --quiet hvt; then
    sudo systemctl restart hvt
fi
if systemctl is-active --quiet hvt-worker; then
    sudo systemctl restart hvt-worker
fi
echo "Deployment complete!"