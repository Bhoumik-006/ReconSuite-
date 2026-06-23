FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for Playwright and common tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl gnupg ca-certificates \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdrm2 libdbus-1-3 libxkbcommon0 libxcomposite1 libxdamage1 \
    libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 \
    libatspi2.0-0 libwayland-client0 libwayland-egl1-mesa \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Chromium browser
RUN playwright install chromium
RUN playwright install-deps chromium

# Copy application files
COPY recon_cli.py app.py ./
COPY templates/ ./templates/
COPY static/ ./static/ 2>/dev/null || true
COPY scans/ ./scans/ 2>/dev/null || true

# Create required directories
RUN mkdir -p reports screenshots

# Default environment
ENV FLASK_SECRET=reconsuite-v2-change-me-in-production
ENV PORT=5000
ENV FLASK_DEBUG=0

EXPOSE 5000

# Run the Flask dashboard by default
CMD ["python", "app.py"]
