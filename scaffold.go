package goscaffold

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

const (
	// DefaultGraceTimeout is the default amount of time to wait for a request
	// to complete. Default is 30 seconds, which is also the default grace period
	// in Kubernetes.
	DefaultGraceTimeout = 30 * time.Second
)

/*
ErrSignalCaught is used in the "Shutdown" mechanism when the shutdown was
caused by a SIGINT or SIGTERM.
*/
var ErrSignalCaught = errors.New("Caught shutdown signal")

/*
An HTTPScaffold provides a set of features on top of a standard HTTP
listener. It includes an HTTP handler that may be plugged in to any
standard Go HTTP server. It is intended to be placed before any other
handlers.
*/
type HTTPScaffold struct {
	insecurePort     int
	open             bool
	tracker          *requestTracker
	insecureListener net.Listener
}

/*
CreateHTTPScaffold makes a new scaffold. The default scaffold will
do nothing.
*/
func CreateHTTPScaffold() *HTTPScaffold {
	return &HTTPScaffold{}
}

/*
SetInsecurePort sets the port number to listen on in regular "HTTP" mode.
It may be set to zero, which indicates to listen on an ephemeral port.
It must be called before "listen".
*/
func (s *HTTPScaffold) SetInsecurePort(ip int) {
	s.insecurePort = ip
}

/*
InsecureAddress returns the actual address (including the port if an
ephemeral port was used) where we are listening. It must only be
called after "Listen."
*/
func (s *HTTPScaffold) InsecureAddress() string {
	return s.insecureListener.Addr().String()
}

/*
Open opens up the port that was created when the scaffold was set up.
This method is optional. It may be called before Listen so that we can
retrieve the actual address where the server is listening before we actually
start to listen.
*/
func (s *HTTPScaffold) Open() error {
	s.tracker = startRequestTracker(DefaultGraceTimeout)

	il, err := net.ListenTCP("tcp", &net.TCPAddr{
		Port: s.insecurePort,
	})
	if err != nil {
		return err
	}
	s.insecureListener = il
	s.open = true
	return nil
}

/*
Listen should be called instead of using the standard "http" and "net"
libraries. It will open a port (or ports) and begin listening for
HTTP traffic. It will block until the server is shut down by
the various methods in this class.
It will use the graceful shutdown logic to ensure that once marked down,
the server will not exit until all the requests have completed,
or until the shutdown timeout has expired.
Like http.Serve, this function will block until we are done serving HTTP.
If "SetInsecurePort" or "SetSecurePort" were not set, then it will listen on
a dynamic port.
Listen will block until the server is shutdown using "Shutdown" or one of
the other shutdown mechanisms. It must not be called until after "Open"
has been called.
If shut down, Listen will return the error that was passed to the "shutdown"
method.
*/
func (s *HTTPScaffold) Listen(baseHandler http.Handler) error {
	if !s.open {
		err := s.Open()
		if err != nil {
			return err
		}
		s.open = true
	}

	handler := &httpHandler{
		s:       s,
		handler: baseHandler,
	}
	go http.Serve(s.insecureListener, handler)
	err := <-s.tracker.C
	s.insecureListener.Close()
	return err
}

/*
Shutdown indicates that the server should stop handling incoming requests
and exit from the "Serve" call. This may be called automatically by
calling "CatchSignals," or automatically using this call.
*/
func (s *HTTPScaffold) Shutdown(reason error) {
	s.tracker.shutdown(reason)
}

/*
CatchSignals directs the scaffold to listen for common signals. It catches
three signals. SIGINT (aka control-C) and SIGTERM (what "kill" sends by default)
will cause the program to be marked down, and "SignalCaught" will be returned
by the "Listen" method. SIGHUP ("kill -1" or "kill -HUP") will cause the
stack trace of all the threads to be printed to stderr, just like a Java program.
*/
func (s *HTTPScaffold) CatchSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	signal.Notify(sigChan, syscall.SIGTERM)
	signal.Notify(sigChan, syscall.SIGHUP)

	go func() {
		for {
			sig := <-sigChan
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				s.Shutdown(ErrSignalCaught)
				signal.Reset()
				return
			case syscall.SIGHUP:
				dumpStack()
			}
		}
	}()
}

func dumpStack() {
	stackSize := 32767
	stackBuf := make([]byte, stackSize)
	var w int

	for w < stackSize {
		w = runtime.Stack(stackBuf, true)
		if w == stackSize {
			stackSize *= 2
			stackBuf = make([]byte, stackSize)
		}
	}

	fmt.Fprint(os.Stderr, string(stackBuf[:w]))
}

type httpHandler struct {
	s       *HTTPScaffold
	handler http.Handler
}

func (h *httpHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	startErr := h.s.tracker.start()
	if startErr == nil {
		h.handler.ServeHTTP(resp, req)
		h.s.tracker.end()
	} else {
		mt := SelectMediaType(req, []string{"text/plain", "application/json"})
		resp.Header().Set("Content-Type", mt)
		resp.WriteHeader(http.StatusServiceUnavailable)
		switch mt {
		case "application/json":
			re := map[string]string{
				"error":   "Stopping",
				"message": startErr.Error(),
			}
			buf, _ := json.Marshal(&re)
			resp.Write(buf)
		default:
			resp.Write([]byte(startErr.Error()))
		}
	}
}
