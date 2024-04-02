package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"golang.org/x/sync/errgroup"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsimple"
)

var (
	flagConfig string
	flagDebug  bool
	mapper     = &[]*Mapper{}
)

func init() {
	flag.StringVar(&flagConfig, "c", "config.hcl", "Path to the configuration file")
	flag.BoolVar(&flagDebug, "d", true, "EnablE deBuG mode")
}

type PreConfig struct {
	Upstreams    []*Upstream    `hcl:"upstream,block"`
	Certificates []*Certificate `hcl:"certificate,block"`
	Remain       hcl.Body       `hcl:",remain"`
}

// Config represents the configuration for the proxy server
type Config struct {
	Includes     []*Upstream    `hcl:"include,optional"`
	Upstreams    []*Upstream    `hcl:"upstream,block"`
	Certificates []*Certificate `hcl:"certificate,block"`
	Domains      []*Domain      `hcl:"domain,block"`
}

// Upstream represents a backend service
type Upstream struct {
	Name string `hcl:"name,label"`
	Addr string `hcl:"addr"`
}

// Certificate represents a TLS certificate
type Certificate struct {
	Name string          `hcl:"name,label"`
	File CertificateFile `hcl:"file,block"`
}

// CertificateFile represents the file paths for a TLS certificate
type CertificateFile struct {
	PrivateKey  string `hcl:"private_key"`
	Certificate string `hcl:"certificate"`
}

// Service represents a service configuration
type Domain struct {
	Name             string   `hcl:"name,label"`
	IP               string   `hcl:"listen,optional"`
	Logging          Logging  `hcl:"logging,block"`
	Hosts            []string `hcl:"alt_hosts,optional"`
	Paths            []*Path  `hcl:"path,block"`
	Certificate      *string  `hcl:"certificate"`
	RedirectInsecure bool     `hcl:"redirect_to_https,optional"`
}

// Logging represents the logging configuration
type Logging struct {
	Type     string `hcl:"type,optional"`
	Output   string `hcl:"output,optional"`
	LogLevel string `hcl:"log_level"` // New: Define log level per listener/service
}

type Path struct {
	Path          string            `hcl:"path,label"`
	AddHeaders    map[string]string `hcl:"add_headers,optional"`
	RemoveHeaders map[string]string `hcl:"del_headers,optional"`
	Upstream      *string           `hcl:"upstream,optional" cty:"upstream,optional"`
	Logging       *Logging          `hcl:"logging,block"` // New: Allow per-listener logging config
}

type Mapper struct {
	key       string
	Host      string
	Path      string
	PathRegex *regexp.Regexp
	Upstream  *httputil.ReverseProxy
}

func main() {
	flag.Parse()

	var g errgroup.Group
	var c []byte

	var ectx = &hcl.EvalContext{
		Variables: map[string]cty.Value{
			// listeners
			"default_server": cty.StringVal(":80"),

			// Outputs
			"stdout": cty.StringVal("stdout"),
			"stderr": cty.StringVal("stderr"),

			// LogLevels
			"INFO":  cty.StringVal("INFO"),
			"WARN":  cty.StringVal("WARN"),
			"ERROR": cty.StringVal("ERROR"),

			// LoggerTypes
			"json":  cty.StringVal("json"),
			"plain": cty.StringVal("plain"),

			// Protocols
			"http":  cty.StringVal("80"),
			"https": cty.StringVal("443"),
			"ssh":   cty.StringVal("22"),

			//
			"upstream":    cty.MapValEmpty(cty.String),
			"certificate": cty.MapValEmpty(cty.String),
		},
		Functions: map[string]function.Function{
			// Define custom functions if needed
		},
	}

	// Read the configuration from the file
	if len(flagConfig) > 0 {
		b, err := os.ReadFile(flagConfig)
		if err != nil {
			log.Fatalf("Failed to read config file: %v", err)
		}

		c = append(c, b...)
	}

	// Load the configuration for settings we care about right now
	// which includes upstream and certificates
	var precfg PreConfig
	_ = hclsimple.Decode(flagConfig, c, ectx, &precfg)

	//
	var ectxUpstreams = map[string]cty.Value{}
	for _, v := range precfg.Upstreams {
		ectxUpstreams[v.Name] = cty.StringVal(v.Addr)
	}
	ectx.Variables["upstream"] = cty.ObjectVal(ectxUpstreams)

	//
	var ectxCerts = map[string]cty.Value{}
	for _, v := range precfg.Certificates {
		ectxCerts[v.Name] = cty.StringVal(v.Name)
	}
	ectx.Variables["certificate"] = cty.ObjectVal(ectxCerts)

	// Once more time with feeling.
	// will parse the full configuration using the seeded context
	var config Config
	err := hclsimple.Decode(flagConfig, c, ectx, &config)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if flagDebug {
		fmt.Println("Upstreams\n====================")
		for _, d := range config.Upstreams {
			fmt.Printf("upstream.%s -> %s\n", d.Name, d.Addr)
		}

		fmt.Println("\n\nCertificates\n====================")
		for _, d := range config.Certificates {
			fmt.Printf("certificate.%s -> %s\n", d.Name, d.File.Certificate)
		}

		fmt.Println("\n\nDomains\n====================")
		for _, d := range config.Domains {
			fmt.Printf("domain.%s\n", strings.ReplaceAll(d.Name, ".", "_"))
			for _, p := range d.Paths {
				fmt.Printf("\t- path: %s -> %s\n", p.Path, *p.Upstream)
			}
		}
	}

	// Upstreams is a mapping of upstream names to their reverse proxy
	var upstreams = &map[string]*httputil.ReverseProxy{}
	var mapKeys = make(map[string]struct{})

	// Iterate over services and start servers based on protocol
	for _, domain := range config.Domains {
		var compiledHosts = []string{domain.Name}
		if len(domain.Hosts) > 0 {
			compiledHosts = append(compiledHosts, domain.Hosts...)
		}

		for _, host := range compiledHosts {
			for _, path := range domain.Paths {
				regex, _ := regexp.Compile(path.Path)

				targetURL, err := url.Parse(*path.Upstream)
				if err != nil {
					log.Fatalf("Failed to parse upstream URL %s for service %s: %v", *path.Upstream, domain.Name, err)
				}

				if _, ok := (*upstreams)[*path.Upstream]; !ok {
					proxy := httputil.NewSingleHostReverseProxy(targetURL)
					proxy.Director = func(req *http.Request) {
						// TODO: Add conditional logging for requests
						req.Header.Add("X-Forwarded-Host", req.Host)
						req.Header.Add("X-FlightPath-Service-Name", domain.Name)
						req.Header.Add("X-FlightPath-Host-Name", host)
						req.Header.Add("X-FlightPath-Path-Match", path.Path)

						if path.AddHeaders != nil {
							for key, value := range path.AddHeaders {
								req.Header.Add(key, value)
							}
						}

						if path.RemoveHeaders != nil {
							for key := range path.RemoveHeaders {
								req.Header.Del(key)
							}
						}

						req.URL.Scheme = targetURL.Scheme
						req.URL.Host = targetURL.Host
						req.URL.Path = singleJoiningSlash(targetURL.Path, req.URL.Path)
					}

					proxy.ModifyResponse = func(response *http.Response) error {
						log.Printf("[%s] %s %s %d %d", "INFO", host, response.Request.URL, response.StatusCode, response.ContentLength)
						return nil
					}
					(*upstreams)[*path.Upstream] = proxy

				}

				var mapKey = fmt.Sprintf("%s-%s", host, path.Path)
				// Add the path to the mapper
				if _, ok := mapKeys[mapKey]; ok {
					if flagDebug {
						log.Printf("Skipping duplicate path %s for service %s, host %s", path.Path, domain.Name, host)
					}
					continue
				}

				(*mapper) = append((*mapper), &Mapper{
					key:       mapKey,
					Host:      host,
					Path:      path.Path,
					PathRegex: regex,
					Upstream:  (*upstreams)[*path.Upstream],
				})
			}
		}
	}

	// TODO: add static IP binding per service/domain/host
	// TODO: Add better logging
	mux := http.NewServeMux()

	// Start an HTTP server and listen on a port.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var proxy *httputil.ReverseProxy

		for _, m := range *mapper {
			if m.PathRegex.MatchString(r.URL.Path) && r.Host == m.Host {
				proxy = m.Upstream
				break
			}
		}

		if proxy == nil {
			// Handle unknown hostnames, perhaps with an HTTP error.
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}

		// Use the reverse proxy to handle the request for the target host.
		proxy.ServeHTTP(w, r)
	})

	g.Go(func() func() error {
		return func() error {
			var err error
			log.Println("HTTP Server is starting...")

			srv := &http.Server{
				Addr:    ":80",
				Handler: mux,
			}

			if err := srv.ListenAndServe(); err != nil {
				log.Fatalf("Failed to start server: %v", err)
			}
			return err
		}
	}())

	g.Go(func() func() error {
		return func() error {
			var err error

			srv := &http.Server{
				Addr:    ":443",
				Handler: mux,
			}

			log.Println("HTTP(S) Server is starting...")

			certs, err := getCertificates(&config)
			if err != nil {
				return err
			}
			srv.TLSConfig = &tls.Config{
				Certificates: certs,
			}

			return srv.ListenAndServeTLS("", "")
		}
	}())

	// Wait for all servers to finish
	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}

// getCertificates returns a collection of TLS certificate based on the certificate name
func getCertificates(config *Config) ([]tls.Certificate, error) {
	var collection = []tls.Certificate{}
	for _, cert := range config.Certificates {
		tlsCert, err := tls.LoadX509KeyPair(cert.File.Certificate, cert.File.PrivateKey)
		if err != nil {
			return nil, err
		}
		collection = append(collection, tlsCert)
	}

	return collection, nil
}

// singleJoiningSlash ensures the final URL path is correctly formed
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
