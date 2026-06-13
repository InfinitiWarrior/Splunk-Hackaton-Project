FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi-dev \
    shared-mime-info \
    curl \
    docker.io \
    && rm -rf /var/lib/apt/lists/*
RUN pip install uv
COPY requirements.txt .
RUN uv pip install --system -r requirements.txt
RUN pip install pyvelociraptor grpcio --root-user-action=ignore
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
