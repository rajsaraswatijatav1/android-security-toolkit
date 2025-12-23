# Android Security Toolkit v2.0 - Dockerfile
# Multi-stage build for production deployment

FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # ADB tools
    android-tools-adb \
    android-tools-fastboot \
    # Network tools
    nmap \
    tcpdump \
    net-tools \
    # Build tools
    gcc \
    g++ \
    make \
    # Utilities
    curl \
    wget \
    git \
    sqlite3 \
    # Java for APK analysis
    default-jre \
    default-jdk \
    # Clean up
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 astuser && \
    mkdir -p /app /loot && \
    chown -R astuser:astuser /app /loot

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/astuser/.local

# Copy application code
COPY . .

# Set ownership
RUN chown -R astuser:astuser /app

# Switch to non-root user
USER astuser

# Add local bin to PATH
ENV PATH="/home/astuser/.local/bin:$PATH"

# Create necessary directories
RUN mkdir -p /loot/extracted_data /loot/logs /loot/screenshots /loot/network

# Set Python path
ENV PYTHONPATH="/app:$PYTHONPATH"

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default command
CMD ["python", "main.py", "--help"]