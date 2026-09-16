FROM python:3.12-alpine
COPY listener.py /listener.py
USER nobody
EXPOSE 8080/tcp 8080/udp
CMD ["python", "-u", "/listener.py"]
