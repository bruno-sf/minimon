FROM alpine

WORKDIR /usr/app

COPY ./ ./

RUN apk add --update python3

ENTRYPOINT ["/usr/bin/python3", "-u", "minimon.py"]
