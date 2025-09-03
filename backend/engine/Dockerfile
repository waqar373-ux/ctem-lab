FROM python:3.12-slim
WORKDIR /app
RUN pip install psycopg[binary]==3.2.1
COPY engine.py .
CMD ["python","engine.py"]
