FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir psycopg[binary]==3.2.1 ansible-core==2.16.6 paramiko==3.4.0
ENV ANSIBLE_HOST_KEY_CHECKING=False
RUN mkdir -p /app/.ssh
COPY run_action.py .
CMD ["python","-u","run_action.py"]
