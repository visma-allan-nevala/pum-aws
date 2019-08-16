FROM python
COPY pum_aws.py requirements.txt /root/
WORKDIR /root
RUN pip install -r requirements.txt
ENTRYPOINT ["python","pum_aws.py"]