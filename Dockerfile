FROM scratch
MAINTAINER idanz@il.ibm.com

COPY kactivator /
ENTRYPOINT ["/kactivator"]
