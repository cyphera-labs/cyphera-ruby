FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache ruby-3.1 && rm -rf /var/cache/apk/*

USER nonroot
WORKDIR /home/nonroot
COPY --chown=nonroot:nonroot . .
CMD ["ruby", "test/test_all.rb"]
