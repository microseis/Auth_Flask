FROM python:3.9 as base

ENV PYTHONBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

RUN apt-get update
RUN pip3 install --upgrade pip

COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

FROM base as dev

RUN mkdir "opt/app"

COPY src /opt/app

WORKDIR /opt/app

EXPOSE 8000:8000

CMD ["python3", "pywsgi.py"]


