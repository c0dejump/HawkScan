FROM python:3.7-alpine
RUN apk update
RUN apk add libffi libffi-dev gcc g++ make openssl-dev openssl openssh curl
WORKDIR /root
COPY . /root/HawkScan
WORKDIR /root/HawkScan

# Get Rust for python cryptography
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN pip install -r requirements.txt && \
    rm -rf .git && \
    apk del libffi-dev gcc g++ make openssl-dev curl && \
    rm -rf /var/cache/apk/*
ENTRYPOINT ["python", "hawkscan.py"]
