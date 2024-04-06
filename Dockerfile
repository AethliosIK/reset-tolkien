FROM python:3.10-alpine

WORKDIR /reset-tolkien/
ADD . /reset-tolkien/

RUN python setup.py install 

ENTRYPOINT ["reset-tolkien"]