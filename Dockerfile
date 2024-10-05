FROM alpine:3

WORKDIR /app

COPY --chmod=755 dnsseeder dnsseeder
COPY configs/dogecoin.json dogecoin.json

EXPOSE 53:53
EXPOSE 8053:8053

CMD [ "/app/dnsseeder", "-netfile", "dogecoin.json", "-s", "-w", "8053", "-p", "53" ]