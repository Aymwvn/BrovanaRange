FROM python:3.11-alpine

WORKDIR /app
RUN pip install --no-cache-dir Flask==3.1.1 \
    && addgroup -S honeypot \
    && adduser -S -G honeypot -h /app honeypot
COPY app.py /app/app.py
USER honeypot

EXPOSE 8080
CMD ["python", "/app/app.py"]
