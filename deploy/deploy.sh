#!/bin/bash
# Simple manual deployment script (if not using GitHub Actions)

cd /home/hvt/hvt
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py collectstatic --noinput

echo "Gracefully reloading Gunicorn..."
kill -HUP $(cat /tmp/hvt-gunicorn.pid)
echo "Deployment complete!"