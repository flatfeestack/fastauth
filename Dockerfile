FROM golang:1.14
WORKDIR /app
COPY . .
RUN make
CMD ["./fastauth", "-dev", "test"]
