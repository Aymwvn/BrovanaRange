FROM python:3.11-slim
RUN apt update && apt install -y --no-install-recommends curl procps iputils-ping && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash student
WORKDIR /app
RUN pip install --no-cache-dir flask
COPY app.py /app/app.py
RUN echo 'REDRANGE{placeholder_dynamic_flag}' > /flag.txt && chmod 644 /flag.txt && chown root:root /flag.txt && chown -R student:student /app
USER student
EXPOSE 8080
CMD ["python", "/app/app.py"]
