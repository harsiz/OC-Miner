// Package solo implements solo mining directly against the OmegaCases API:
//
//	GET  {api}/api/mining  -> {"target": "...", "previous_hash": "..."}
//	POST {api}/api/mining  {"miner_id", "nonce", "hash"} -> 200 accepted / 409 stale
package solo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/harsiz/oc-miner/internal/engine"
	"github.com/harsiz/oc-miner/internal/job"
	"github.com/harsiz/oc-miner/internal/minerdevice"
)

type blockInfo struct {
	Target       string `json:"target"`
	PreviousHash string `json:"previous_hash"`
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func fetchBlock(api string) (*blockInfo, error) {
	resp, err := httpClient.Get(api + "/api/mining")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var info blockInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Run drives the solo mining loop until stop is signalled, using dev to
// search nonces. Safe to run in its own goroutine; progress and results are
// reported over msgs. The caller owns dev and should Close() it once Run
// returns.
func Run(api, minerID string, dev minerdevice.Device, msgs chan<- engine.Msg, stop *engine.StopFlag) {
	api = strings.TrimRight(api, "/")
	log := func(s string) { msgs <- engine.Msg{Kind: engine.MsgLog, Text: s} }

	log(fmt.Sprintf("Starting solo miner | Address: %s", minerID))
	log(fmt.Sprintf("API: %s", api))

	m := dev
	msgs <- engine.Msg{Kind: engine.MsgAdapterName, Text: m.Name()}
	log(fmt.Sprintf("Device: %s (%d hashes/batch)", m.Name(), m.BatchSize()))
	msgs <- engine.Msg{Kind: engine.MsgStatus, Text: "Mining"}

	var totalHashes, blocksFound uint64
	rateWindowStart := time.Now()
	var rateWindowHashes uint64

	for !stop.IsStopped() {
		log("Fetching new block template...")
		info, err := fetchBlock(api)
		if err != nil {
			log(fmt.Sprintf("Network error: %v", err))
			log("Retrying in 5s...")
			time.Sleep(5 * time.Second)
			continue
		}

		j, err := job.New(info.PreviousHash, minerID, info.Target)
		if err != nil {
			log(fmt.Sprintf("Bad job data: %v", err))
			time.Sleep(5 * time.Second)
			continue
		}
		log("Target:    " + info.Target)
		log("Prev hash: " + info.PreviousHash)

		baseNonce := uint64(0)
		lastCheck := time.Now()

	inner:
		for {
			if stop.IsStopped() {
				return
			}

			result, err := m.SearchBatch(j, baseNonce)
			if err != nil {
				log(fmt.Sprintf("Device error: %v", err))
				break inner
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
					BlocksFound: blocksFound,
				}
				rateWindowHashes = 0
				rateWindowStart = time.Now()
			}

			if result != nil {
				verifyHash := j.HashNonce(result.Nonce)
				if verifyHash != result.HashHex || !j.MeetsTarget(verifyHash) {
					log("Result failed local verification, discarding and continuing.")
					continue
				}
				log(fmt.Sprintf("✔ Block found! Nonce=%d Hash=%s", result.Nonce, result.HashHex))
				log("  Submitting...")

				body, _ := json.Marshal(map[string]any{
					"miner_id": minerID,
					"nonce":    result.Nonce,
					"hash":     result.HashHex,
				})
				resp, err := httpClient.Post(api+"/api/mining", "application/json", bytes.NewReader(body))
				if err != nil {
					log(fmt.Sprintf("Submit error: %v", err))
				} else {
					respBody := readAll(resp)
					switch resp.StatusCode {
					case 200:
						blocksFound++
						log(fmt.Sprintf("✔ Block accepted! %s", respBody))
					case 409:
						log("✘ Stale - another miner was faster.")
					default:
						log(fmt.Sprintf("✘ Server returned %d: %s", resp.StatusCode, respBody))
					}
				}
				break inner
			}

			if time.Since(lastCheck) >= 15*time.Second {
				lastCheck = time.Now()
				if check, err := fetchBlock(api); err == nil && check.PreviousHash != info.PreviousHash {
					log("⟳ New block detected - restarting...")
					break inner
				}
			}
		}
	}

	msgs <- engine.Msg{Kind: engine.MsgStatus, Text: "Stopped"}
}

func readAll(resp *http.Response) string {
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	return buf.String()
}
