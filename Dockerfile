#Projeto minimon - Dockerfile - brunof 21/01/2020
#FROM python:alpine
FROM alpine

WORKDIR /usr/app

COPY ./ ./

RUN apk add --update python3
#ENTRYPOINT ["/minimon.py"]
CMD ./minimon.py
