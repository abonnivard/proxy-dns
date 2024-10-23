# Use a lightweight Python base image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install any needed packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the DNS port
EXPOSE 53/udp

# Set environment variables (if needed)
ENV PYTHONUNBUFFERED=1

# Run the proxy when the container starts
CMD ["python3", "proxy.py"]
