FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY *.py .

# Make ports available
EXPOSE 5000
EXPOSE 5001
EXPOSE 5002

# Command to run when starting the container
CMD ["python", "siem_architecture.py"]