package goscaffold

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Scaffold Tests", func() {
	It("Validate framework", func() {
		s := CreateHTTPScaffold()
		stopChan := make(chan bool)
		err := s.Open()
		Expect(err).Should(Succeed())

		go func() {
			fmt.Fprintf(GinkgoWriter, "Gonna listen on %s\n", s.InsecureAddress())
			s.Listen(&testHandler{})
			fmt.Fprintf(GinkgoWriter, "Done listening\n")
			stopChan <- true
		}()

		Eventually(func() bool {
			return testGet(s, "")
		}, 5*time.Second).Should(BeTrue())
		resp, err := http.Get(fmt.Sprintf("http://%s", s.InsecureAddress()))
		Expect(err).Should(Succeed())
		Expect(resp.StatusCode).Should(Equal(200))
		s.Shutdown(errors.New("Validate"))
		Eventually(stopChan).Should(Receive(BeTrue()))
	})

	It("Shutdown", func() {
		s := CreateHTTPScaffold()
		stopChan := make(chan bool)
		err := s.Open()
		Expect(err).Should(Succeed())

		go func() {
			s.Listen(&testHandler{})
			stopChan <- true
		}()

		go func() {
			resp2, err2 := http.Get(fmt.Sprintf("http://%s?delay=1s", s.InsecureAddress()))
			Expect(err2).Should(Succeed())
			Expect(resp2.StatusCode).Should(Equal(200))
		}()

		// Just make sure server is listening
		Eventually(func() bool {
			return testGet(s, "")
		}, 5*time.Second).Should(BeTrue())

		// Previous call prevents server from exiting
		Consistently(stopChan, 250*time.Millisecond).ShouldNot(Receive())

		// Tell the server to try and exit
		s.Shutdown(errors.New("Stop"))
		// Should take one second -- in the meantime, calls should fail with 503
		resp, err := http.Get(fmt.Sprintf("http://%s?", s.InsecureAddress()))
		Expect(err).Should(Succeed())
		Expect(resp.StatusCode).Should(Equal(503))
		// But in less than two seconds, server should be down
		Eventually(stopChan, 2*time.Second).Should(Receive(BeTrue()))
		// Calls should now fail
		Eventually(func() bool {
			return testGet(s, "")
		}, time.Second).Should(BeFalse())
	})
})

func testGet(s *HTTPScaffold, path string) bool {
	resp, err := http.Get(fmt.Sprintf("http://%s", s.InsecureAddress()))
	if err != nil {
		fmt.Fprintf(GinkgoWriter, "Get %s = %s\n", path, err)
		return false
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(GinkgoWriter, "Get %s = %d\n", path, resp.StatusCode)
		return false
	}
	return true
}

type testHandler struct {
}

func (h *testHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	var err error
	var delayTime time.Duration

	delayStr := req.URL.Query().Get("delay")
	if delayStr != "" {
		delayTime, err = time.ParseDuration(delayStr)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	if delayTime > 0 {
		time.Sleep(delayTime)
	}
}
