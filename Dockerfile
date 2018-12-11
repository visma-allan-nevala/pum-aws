FROM python
COPY pum-aws.py requirements.txt /root/
WORKDIR /root
RUN pip install -r requirements.txt
ENTRYPOINT ["python","pum-aws.py"]