FROM python:3.12-slim
WORKDIR /app
COPY app.py README.md START-HERE.txt ./
COPY dist ./dist
RUN mkdir -p /data && useradd --system --uid 10001 lantern && chown -R lantern:lantern /app /data
ENV DATA_DIR=/data HOST=0.0.0.0 PORT=8000 OPEN_BROWSER=0
USER lantern
EXPOSE 8000
CMD ["python", "app.py"]
