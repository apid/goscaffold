package goscaffold

import (
	"fmt"
	"net/http"
)

func Example() {
	// Create a new scaffold that will listen for HTTP on port 8080
	scaf := CreateHTTPScaffold()
	scaf.SetInsecurePort(8080)

	// Direct the scaffold to catch common signals and trigger a
	// graceful shutdown.
	scaf.CatchSignals()

	listener := &TestListener{}

	// Listen now. The listener will return when the server is actually
	// shut down.
	err := scaf.Listen(listener)

	// If we get here, and if we care to know, then the error will tell
	// us why we were shut down.
	fmt.Printf("HTTP server shut down: %s\n", err.Error())
}

/*
TestListener is an HTTP listener used for the example code. It just returns
200 and "Hello, World!"
*/
type TestListener struct {
}

func (l *TestListener) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "text/plain")
	resp.WriteHeader(http.StatusOK)
	resp.Write([]byte("Hello, World!"))
}
