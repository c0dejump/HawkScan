FROM python:3.5-alpine
RUN apk update 
RUN apk add git libffi libffi-dev gcc g++ make openssl-dev openssl openssh
WORKDIR /root
RUN git clone https://github.com/c0dejump/HawkScan.git
WORKDIR /root/HawkScan
RUN pip install -r requirements.txt && \
    rm -rf .git && \
    apk del git libffi-dev gcc g++ make openssl-dev && \
    rm -rf /var/cache/apk/*
ENTRYPOINT ["python", "hawkscan.py"]