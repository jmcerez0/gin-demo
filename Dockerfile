FROM golang:alpine

WORKDIR /app

COPY go.mod .

RUN go mod download

COPY . .

RUN go build

EXPOSE 3000

CMD [ "./gin-demo" ]