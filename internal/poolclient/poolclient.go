// Package poolclient implements the miner side of the OC-Miner Pool Protocol
// v1 (see internal/protocol). It connects to a pool over TCP, receives job
// updates, and submits shares it finds.
package poolclient

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harsiz/oc-miner/internal/engine"
	"github.com/harsiz/oc-miner/internal/gpu"
	"github.com/harsiz/oc-miner/internal/job"
	"github.com/harsiz/oc-miner/internal/protocol"
)

func sendMsg(conn net.Conn, mu *sync.Mutex, msg protocol.ClientMsg) error {
	line, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	_, err = conn.Write(append(line, '\n'))
	return err
}

// Run drives the pool mining loop until stop is signalled. Safe to run in
// its own goroutine; progress and results are reported over msgs.
func Run(host string, port int, userID string, msgs chan<- engine.Msg, stop *engine.StopFlag) {
	log := func(s string) { msgs <- engine.Msg{Kind: engine.MsgLog, Text: s} }

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	log(fmt.Sprintf("Connecting to pool %s...", addr))

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log(fmt.Sprintf("Could not connect to pool: %v", err))
		msgs <- engine.Msg{Kind: engine.MsgStatus, Text: "Error"}
		return
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	var writeMu sync.Mutex
	jobCh := make(chan protocol.ServerMsg, 16)

	go func() {
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if line = strings.TrimSpace(line); line != "" {
				var sm protocol.ServerMsg
				if err := json.Unmarshal([]byte(line), &sm); err != nil {
					log(fmt.Sprintf("Pool sent unparsable message: %v", err))
				} else if sm.Type == "ping" {
					_ = sendMsg(conn, &writeMu, protocol.ClientMsg{Type: "pong"})
				} else {
					jobCh <- sm
				}
			}
			if err != nil {
				break
			}
		}
		log("Pool connection closed.")
		close(jobCh)
	}()

	if err := sendMsg(conn, &writeMu, protocol.ClientMsg{Type: "hello", UserID: userID}); err != nil {
		log(fmt.Sprintf("Handshake failed: %v", err))
		return
	}
	log(fmt.Sprintf("Connected. Waiting for work as %s...", userID))

	m, err := gpu.New()
	if err != nil {
		log(fmt.Sprintf("GPU init failed: %v", err))
		msgs <- engine.Msg{Kind: engine.MsgStatus, Text: "Error"}
		return
	}
	defer m.Close()
	msgs <- engine.Msg{Kind: engine.MsgAdapterName, Text: m.AdapterName}
	log(fmt.Sprintf("GPU: %s (%d hashes/dispatch)", m.AdapterName, m.BatchSize()))
	msgs <- engine.Msg{Kind: engine.MsgStatus, Text: "Mining"}

	var currentJob *job.Job
	var baseNonce, totalHashes, sharesFound uint64
	rateWindowStart := time.Now()
	var rateWindowHashes uint64

	for !stop.IsStopped() {
		// drain any pending job/result updates without blocking
	drain:
		for {
			select {
			case sm, ok := <-jobCh:
				if !ok {
					return
				}
				switch sm.Type {
				case "job":
					j, err := job.New(sm.PreviousHash, sm.PoolID, sm.Target)
					if err != nil {
						log(fmt.Sprintf("Bad job from pool: %v", err))
						continue
					}
					log(fmt.Sprintf("New job | prev=%s target=%s", short(sm.PreviousHash), short(sm.Target)))
					currentJob = j
					baseNonce = 0
				case "share_result":
					if sm.Accepted {
						sharesFound++
						log("✔ Share accepted: " + sm.Message)
					} else {
						log("✘ Share rejected: " + sm.Message)
					}
				}
			default:
				break drain
			}
		}

		if currentJob == nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}

		result, err := m.SearchBatch(currentJob, baseNonce)
		if err != nil {
			log(fmt.Sprintf("GPU error: %v", err))
			time.Sleep(time.Second)
			continue
		}
		batchHashes := m.BatchSize()
		baseNonce += batchHashes
		totalHashes += batchHashes
		rateWindowHashes += batchHashes

		if elapsed := time.Since(rateWindowStart); elapsed >= 500*time.Millisecond {
			rate := float64(rateWindowHashes) / elapsed.Seconds()
			msgs <- engine.Msg{
				Kind:        engine.MsgStats,
				Hashrate:    rate,
				TotalHashes: totalHashes,
				SharesFound: sharesFound,
			}
			rateWindowHashes = 0
			rateWindowStart = time.Now()
		}

		if result != nil {
			verifyHash := currentJob.HashNonce(result.Nonce)
			if verifyHash != result.HashHex || !currentJob.MeetsTarget(verifyHash) {
				log("GPU result failed local verification, discarding and continuing.")
				continue
			}
			log(fmt.Sprintf("✔ Share found! Nonce=%d Hash=%s", result.Nonce, result.HashHex))
			if err := sendMsg(conn, &writeMu, protocol.ClientMsg{
				Type:  "share",
				Nonce: result.Nonce,
				Hash:  result.HashHex,
			}); err != nil {
				log(fmt.Sprintf("Submit error: %v", err))
			}
		}
	}

	msgs <- engine.Msg{Kind: engine.MsgStatus, Text: "Stopped"}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
