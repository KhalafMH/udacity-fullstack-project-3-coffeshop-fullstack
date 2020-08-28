FROM python:3.8

COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5000
CMD gunicorn -w 4 -b 0.0.0.0:5000 src.api:app
