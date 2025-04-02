# Python base image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy only the requirements.txt first (for Docker caching)
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy your server code into the container
COPY ./ /app

# Expose the necessary port (50051 in this case)
EXPOSE 50051

# Run your Python server script
CMD ["python", "AIAnalyzer.py", "&"]
