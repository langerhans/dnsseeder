FROM alpine:3

WORKDIR /app

ADD dnsseeder .
ADD configs/dogecoin.json .

RUN chmod +x dnsseeder

EXPOSE 53:53
EXPOSE 8053:8053

CMD [ "./dnsseeder", "-netfile", "dogecoin.json", "-s", "-w", "8053", "-p", "53" ]