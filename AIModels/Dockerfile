# Python base image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy your server code into the container
COPY ./ /app

# Install dependencies (add any necessary dependencies like scikit-learn, etc.)
RUN pip install --no-cache-dir -r requirements.txt

# Expose the necessary port (50051 in this case)
EXPOSE 50051

# Run your Python server script
CMD ["python", "AIAnalyzer.py", "&"]
