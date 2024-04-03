FlightPath
-----------

<p align="center">
  <img width="148px" src="https://github.com/mikemackintosh/flightpath/raw/master/.github/flightpath.png">
</p>

FlightPath is a proxy alternative to Caddy, Nginx, Apache, etc. It's designed with flexibility in mind for extremely opinionated projects.

## Example
A basic example for a TLS HTTP service would look like the following, which would proxy requests to `example.net`, `localhost` and `www.example.net` to `http://localhost:3000`. It binds to `:443` and `:80` by default, but can be changed by passing `listen = '1.1.1.1:443`.

```hcl
upstream "docker_service" {
  addr = "http://localhost:3000"
}

certificate "example_cert" {
  file {
    private_key = "/etc/ssl/private/example.key"
    certificate = "/etc/ssl/certs/example.crt"
  }
}

domain "example.net" {
  logging {
    type     = json
    output   = stdout
    log_level = "DEBUG" // Default service-wide log level
  }

  certificate = certificate.example_cert

  alt_hosts = [ "www.example.net", "localhost" ]

  path "/" {
    upstream = upstream.docker_service
  }
}
```