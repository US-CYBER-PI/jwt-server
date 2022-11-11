FROM golang:1.19-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . ./

RUN go build -o /app/jwt-server .

FROM alpine

WORKDIR /app

COPY --from=builder /app/jwt-server ./jwt-server

CMD ["./jwt-server"]