FROM golang:alpine as builder

WORKDIR /src/app
COPY go.mod go.sum ./
RUN go mod download

COPY  main.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server .


FROM alpine
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /src/app ./app
CMD ["./app/server"]
