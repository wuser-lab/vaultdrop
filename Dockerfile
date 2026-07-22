FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /vaultdrop ./cmd/vaultdrop
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /vaultdrop /vaultdrop
ENTRYPOINT ["/vaultdrop"]
