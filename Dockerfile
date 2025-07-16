FROM python:3.13-alpine
COPY pum_aws.py requirements.txt /root/
WORKDIR /root
RUN pip install -r requirements.txt
ENTRYPOINT ["python","pum_aws.py"]
