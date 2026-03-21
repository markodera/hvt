# ----- Base image -----
FROM python:3.12-slim-bookworm AS base

# Prevent Python from writing .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# ----- Dependencies -----
FROM base AS deps

# System packages required by psycopg2 and Argon2
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ----- Production -----
FROM base AS production

# Install only the runtime lib (not build-essential)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 && \
    rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from deps stage
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

# Create non-root user
RUN useradd --create-home --shell /bin/bash hvt

# Copy application code
COPY . .

# Copy and set entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Collect static files (needs STATIC_ROOT set at build time)
RUN STATIC_ROOT=/app/staticfiles python manage.py collectstatic --noinput || true

# Switch to non-root user
USER hvt

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]