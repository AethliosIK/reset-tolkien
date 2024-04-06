FROM python:3.11-alpine

WORKDIR /reset-tolkien/
ADD . /reset-tolkien/

RUN python setup.py install 

ENTRYPOINT ["reset-tolkien"]