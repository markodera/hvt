#!/bin/bash
# Simple manual deployment script (if not using GitHub Actions)
set -euo pipefail

cd /home/hvt/hvt
git pull origin main
source venv/bin/activate
pip install -r requirements.txt

# Ensure production secrets exist in .env if not already set
if [ -f .env ]; then
  if ! grep -q "HVT_JWT_PRIVATE_KEY=" .env; then
    echo "Generating production HVT_JWT_PRIVATE_KEY in .env..."
    KEY=$(python -c "from cryptography.hazmat.primitives.asymmetric import rsa; from cryptography.hazmat.primitives import serialization; priv = rsa.generate_private_key(65537, 2048); print(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode().replace('\n', '\\\n'))")
    printf '\nHVT_JWT_PRIVATE_KEY="%s"\n' "$KEY" >> .env
  fi
  if ! grep -q "HVT_ENCRYPTION_KEYS=" .env; then
    echo "Generating production HVT_ENCRYPTION_KEYS in .env..."
    ENC_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    printf '\nHVT_ENCRYPTION_KEYS="%s"\n' "$ENC_KEY" >> .env
  fi
fi

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