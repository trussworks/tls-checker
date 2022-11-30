FROM alpine:20221110
COPY tls-checker /bin/tls-checker
ENTRYPOINT [ "tls-checker" ]
