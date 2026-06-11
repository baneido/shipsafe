// Test cases for rules/sast/go.yml (semgrep --test format).
package main

import (
	"fmt"
	"os"
	"os/exec"
)

func emptyErrCheck() {
	_, err := os.Open("config.yml")
	// ruleid: ai-go-empty-error-check
	if err != nil {
	}

	_, err2 := os.Open("other.yml")
	// ok: ai-go-empty-error-check
	if err2 != nil {
		fmt.Println("failed to open:", err2)
	}
}

func discardedError() {
	var data []byte
	// ruleid: ai-go-discarded-error
	f, _ := os.Open("config.yml")
	_ = f
	// ok: ai-go-discarded-error
	n, err := os.Stdout.Write(data)
	_ = n
	_ = err
}

func loopCapture(items []string) {
	for i, item := range items {
		// ruleid: ai-go-goroutine-loop-capture
		go func() {
			fmt.Println(i, item)
		}()
	}

	// ok: ai-go-goroutine-loop-capture
	for i, item := range items {
		go func(idx int, v string) {
			fmt.Println(idx, v)
		}(i, item)
	}
}

func shellConcat(host string) {
	// ruleid: ai-go-shell-command-concat
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	_ = cmd
	// ruleid: ai-go-shell-command-concat
	cmd2 := exec.Command("bash", "-c", fmt.Sprintf("ping -c 1 %s", host))
	_ = cmd2
	// ok: ai-go-shell-command-concat
	cmd3 := exec.Command("ping", "-c", "1", host)
	_ = cmd3
}
