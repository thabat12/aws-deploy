FROM golang:1.22.3-alpine as build

WORKDIR /app
COPY . .

RUN go build -o app.exe main.go
RUN echo hi

FROM alpine:latest

WORKDIR /app

COPY --from=build /app/app.exe .
EXPOSE 8080

CMD ["./app.exe"]