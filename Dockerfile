FROM python:3.10-alpine

WORKDIR /reset-tolkien/
ADD . /reset-tolkien/

RUN pip install --no-cache-dir -r requirements.txt && python setup.py install

ENTRYPOINT ["reset-tolkien"]