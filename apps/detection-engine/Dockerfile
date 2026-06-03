FROM golang:1.23-alpine AS build

RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /detection-engine ./cmd/detection-engine

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /detection-engine /detection-engine

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/detection-engine"]
