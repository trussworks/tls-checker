FROM alpine:3
COPY bin/tls-checker /bin/tls-checker
ENTRYPOINT [ "tls-checker" ]
