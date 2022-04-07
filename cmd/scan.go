package cmd

import (
	"bufio"
	"crypto/tls"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/remeh/sizedwaitgroup"
	"github.com/spf13/cobra"
	"github.com/fracturelabs/go-scan-spring/lib"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Initiate scan",
	Long: `Run a scan against target URLs looking for vulnerable services`,
	Run: func(cmd *cobra.Command, args []string) {
		log := options.Logger
		log.Info().Str("target file", options.TargetFile).Msg("Scan initiated")

		scanner, f, err := getScanner(options.TargetFile)
		if err != nil {
			log.Fatal().Err(err).Str("file", options.TargetFile).
				Msg("unable to read source file")
		}
		defer f.Close()

		swg := sizedwaitgroup.New(options.Threads)

		client := getHTTPClient()

		for scanner.Scan() {
			candidate := scanner.Text()
			if candidate == "" {
				return
			}

			for _, candidateURL := range getUrls(candidate) {
				swg.Add()

				go func(url *url.URL) {
					defer swg.Done()
					statusLog := log.Info()

					methods := []string{}

					if options.HTTPGet {
						methods = append(methods, "GET")
					}

					if options.HTTPPost {
						methods = append(methods, "POST")
					}

					sleepNeeded := false
					for _, method := range methods {
						log.Debug().Str("method", method).Str("url", url.String()).Msg("Queuing")

						p := &lib.Processor{
							Logger:         log,
							BaseURL:        url,
							HTTPClient:     client,
							HTTPMethod:     method,
							Identifier:     options.Identifier,
						}

						if sleepNeeded {
							time.Sleep(time.Duration(options.Sleep) * time.Second)
							sleepNeeded = false
						}


						// Baseline Scan
						if options.RunBaseline {
							err := p.Baseline()

							if err != nil {
								log.Error().Err(err).
									Str("url", url.String()).
									Msg("Baseline scan failed")
								return
							}
							
							log.Debug().
								Str("original URL", url.String()).
								Str("final URL", p.FinalBaselineURL.String()).
								Int("Response Code", p.BaselineResponseStatus).
								Msg("Baseline finished")
													
						}


						// Safe Scan
						if options.RunSafe {
							if sleepNeeded {
								time.Sleep(time.Duration(options.Sleep) * time.Second)
								sleepNeeded = false
							}

							err = p.Safe()

							if err != nil {
								log.Error().Err(err).
									Str("url", url.String()).
									Msg("Safe scan failed")
									
								return
							}

							log.Debug().
								Str("original URL", url.String()).
								Str("final URL", p.FinalSafeURL.String()).
								Int("Response Code", p.SafeResponseStatus).
								Msg("Safe finished")
								

							if p.Vulnerable {
								statusLog = log.Warn()
								sleepNeeded = true
							}
						}
						

						
						//TODO: Create a function to look for 'go-scan-spring-whoami' to prevent duplicate runs of Exploit
						if options.RunExploit {
							// Run the exploit

							if sleepNeeded {
								time.Sleep(time.Duration(options.Sleep) * time.Second)
								sleepNeeded = false
							}

							err = p.Exploit()
							sleepNeeded = true

							if err != nil {
								log.Error().Err(err).
									Str("url", url.String()).
									Msg("Exploit scan failed")
								return
							}
							
							log.Debug().
								Str("original URL", url.String()).
								Str("final URL", p.FinalExploitURL.String()).
								Int("Response Code", p.ExploitResponseStatus).
								Msg("Exploit finished")
			

							if p.Vulnerable || p.Exploited {
								statusLog = log.Warn()
							}

							//Reset the logging

							if sleepNeeded {
								time.Sleep(time.Duration(options.Sleep) * time.Second)
								sleepNeeded = false
							}

							err = p.Reset()
							sleepNeeded = true

							if err != nil {
								log.Error().Err(err).
									Str("url", url.String()).
									Msg("Reset scan failed")
								return
							}
							
							log.Debug().
								Str("original URL", url.String()).
								Int("Response Code", p.ResetResponseStatus).
								Msg("Reset finished")
						}

						statusLog.
							Str("Method", p.HTTPMethod).
							Bool("Vulnerable", p.Vulnerable).
							Bool("Exploited", p.Exploited).
							Str("Target URL", url.String()).
							Int("Baseline Status", p.BaselineResponseStatus).
							Int("Safe Status", p.SafeResponseStatus).
							Int("Exploit Status", p.ExploitResponseStatus).
							Str("Verification URL", p.Verification).
							Msg("Finished scanning target")
					}
				}(candidateURL)
			}
		}

		swg.Wait()
		log.Info().Msg("Processing complete")

	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&options.TargetFile, "file", "f", "", 
		"Target URL filename (- for stdin)")

	scanCmd.Flags().IntVarP(&options.Threads, "threads", "t", 5, 
		"Number of threads")

	scanCmd.Flags().IntVarP(&options.Sleep, "sleep", "s", 10, 
		"Time to sleep between exploit steps. This is needed to allow time for deployment.")

	scanCmd.Flags().StringVarP(&options.Identifier, "identifier", "", "go-scan-spring", 
		"Unique scan identifier (used as a password and an exploit filename)")

	scanCmd.Flags().StringVarP(&options.Proxy, "proxy","x", "",
		"Upstream proxy")

	scanCmd.Flags().BoolVarP(&options.FollowRedirect, "follow-redirect", "", false,
		"Follow redirects")

	scanCmd.Flags().BoolVarP(&options.RunBaseline, "run-baseline", "", false,
		"Run a baseline test to see if endpoint is up")

	scanCmd.Flags().BoolVarP(&options.RunSafe, "run-safe", "", false,
		"Run a safe test to see if endpoint is vulnerable")

	scanCmd.Flags().BoolVarP(&options.RunExploit, "run-exploit", "", false,
		"Run an exploit to retrieve the owner of the Tomcat process")

	scanCmd.Flags().BoolVarP(&options.HTTPGet, "http-get", "", true,
		"Test using HTTP GET requests (must set =false to disable)")

	scanCmd.Flags().BoolVarP(&options.HTTPPost, "http-post", "", true,
		"Test using HTTP POST requests (must set =false to disable)")


	scanCmd.MarkPersistentFlagRequired("file")
}

func getScanner(i string) (*bufio.Scanner, *os.File, error) {
	if i == "-" {
		return bufio.NewScanner(os.Stdin), nil, nil
	}

	file, err := os.Open(i)
	if err != nil {
		return nil, nil, err
	}

	return bufio.NewScanner(file), file, nil
}

func getUrls(target string) (c []*url.URL) {

	// Use the provided target if it starts with 'http'
	if strings.HasPrefix(target, "http") {
		u, err := url.Parse(target)
		if err == nil {
			c = append(c, u)
		}

		return

	} else {
		u, err := url.Parse("http://" + target)
		if err == nil {
			c = append(c, u)
		}		
		
		u, err = url.Parse("https://" + target)
		if err == nil {
			c = append(c, u)
		}
	}

	return
}

func getHTTPClient() (*http.Client) {
	log := options.Logger

	transport := &http.Transport {
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}

	if options.Proxy != "" {
		proxyURL, err := url.Parse(options.Proxy)
		if err != nil {
			log.Fatal().Err(err).Str("proxy", options.Proxy).
				Msg("Invalid proxy setting")
		}

		log.Debug().Str("proxyURL", proxyURL.String()).Msg("Setting proxy")
		transport.Proxy = http.ProxyURL(proxyURL)		
	}


	client := &http.Client{
		Transport: transport,
		Timeout: time.Second * 5,
	}

	log.Debug().Bool("FollowRedirect", options.FollowRedirect).Msg("Redirects")
	if ! options.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        }
	}

	return client
}
