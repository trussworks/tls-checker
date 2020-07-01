FROM alpine:3
COPY tls-checker /bin/tls-checker
ENTRYPOINT [ "tls-checker" ]
