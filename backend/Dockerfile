FROM python:3.11-slim

WORKDIR /app

# Install system dependencies required for PostgreSQL and WHOIS
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    whois \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install psycopg2-binary alembic

COPY . .
RUN python ml/fetch_tranco.py

# Expose port
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
