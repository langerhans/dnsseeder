FROM alpine:3

WORKDIR /app

ADD --chmod=755 dnsseeder .
ADD configs/dogecoin.json .

EXPOSE 53:53
EXPOSE 8053:8053

CMD [ "/app/dnsseeder", "-netfile", "dogecoin.json", "-s", "-w", "8053", "-p", "53" ]