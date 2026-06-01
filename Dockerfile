# Base image with Python and Docker CLI installed
FROM python:3.11-slim

# Install Docker CLI so the app can talk to the host's Docker socket
RUN apt-get update && apt-get install -y docker.io git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose FastAPI port
EXPOSE 8080

# Run the driver
CMD ["python", "orchestrator/driver.py"]
