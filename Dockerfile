FROM matseymour/chrome-python:112.0.5615.121-3.11.3
ENV PYTHONUNBUFFERED 1

RUN mkdir -p /code/testing
COPY testing/requirements.txt /code

RUN pip install -r /code/requirements.txt

RUN apt update && apt install nginx -y
