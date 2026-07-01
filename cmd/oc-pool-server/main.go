// Command oc-pool-server is a reference OmegaCases mining pool server.
//
// It implements the operator side documented at
// /developer/docs/mining-pools (answers OmegaCases's raw "PING" liveness
// probe with "PONG", and calls submit-block when the pool solves a block)
// plus the OC-Miner Pool Protocol v1 (see internal/protocol) so this GPU
// miner - or any other client that speaks it - can connect, receive work,
// and submit shares.
//
// You must register the pool yourself first (POST /api/mining/pools, see
// the docs) to obtain a pool id and API key, then run:
//
//	oc-pool-server -listen 0.0.0.0:3333 -pool-id <uuid> -api-key <key>
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harsiz/oc-miner/internal/protocol"
)

type config struct {
	listen      string
	poolID      string
	apiKey      string
	api         string
	shareFactor int64
}

type blockInfo struct {
	Target       string `json:"target"`
	PreviousHash string `json:"previous_hash"`
}

type roundState struct {
	mu           sync.Mutex
	previousHash string
	networkTarget string
	shareTarget  string
	shares       map[string]uint64
}

type client struct {
	conn net.Conn
	mu   sync.Mutex
}

func (c *client) send(msg protocol.ServerMsg) {
	line, err := json.Marshal(msg)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.Write(append(line, '\n'))
}

type clientRegistry struct {
	mu      sync.Mutex
	clients map[*client]struct{}
}

func newClientRegistry() *clientRegistry {
	return &clientRegistry{clients: make(map[*client]struct{})}
}

func (r *clientRegistry) add(c *client) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[c] = struct{}{}
}

func (r *clientRegistry) remove(c *client) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.clients, c)
}

func (r *clientRegistry) broadcast(msg protocol.ServerMsg) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for c := range r.clients {
		c.send(msg)
	}
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

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

func easierTarget(targetHex string, factor int64) string {
	target, ok := new(big.Int).SetString(targetHex, 16)
	if !ok {
		target = big.NewInt(0)
	}
	eased := new(big.Int).Mul(target, big.NewInt(factor))
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	if eased.Cmp(max) > 0 {
		eased = max
	}
	s := eased.Text(16)
	if len(s) < 64 {
		s = strings.Repeat("0", 64-len(s)) + s
	}
	return s
}

func hashFor(previousHash, idClean string, nonce uint64) string {
	h := sha256.New()
	h.Write([]byte(previousHash))
	h.Write([]byte(idClean))
	h.Write([]byte(strconv.FormatUint(nonce, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

func submitBlock(cfg config, nonce uint64, hash string, shares map[string]uint64) {
	sharesList := make([]map[string]any, 0, len(shares))
	for uid, n := range shares {
		sharesList = append(sharesList, map[string]any{"user_id": uid, "shares": n})
	}
	body, _ := json.Marshal(map[string]any{
		"nonce":  nonce,
		"hash":   hash,
		"shares": sharesList,
	})
	url := fmt.Sprintf("%s/api/mining/pools/%s/submit-block", cfg.api, cfg.poolID)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.apiKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[block] submit-block FAILED: %v", err)
		return
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	log.Printf("[block] submit-block response (%d): %s", resp.StatusCode, buf.String())
}

func watchBlocks(cfg config, round *roundState, registry *clientRegistry) {
	for {
		info, err := fetchBlock(cfg.api)
		if err != nil {
			log.Printf("[job] fetch error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		round.mu.Lock()
		if round.previousHash != info.PreviousHash {
			round.previousHash = info.PreviousHash
			round.networkTarget = info.Target
			round.shareTarget = easierTarget(info.Target, cfg.shareFactor)
			round.shares = make(map[string]uint64)
			log.Printf("[job] new block prev=%s network_target=%s share_target=%s",
				short(round.previousHash), short(round.networkTarget), short(round.shareTarget))
			registry.broadcast(protocol.ServerMsg{
				Type:         "job",
				PoolID:       cfg.poolID,
				PreviousHash: round.previousHash,
				Target:       round.shareTarget,
			})
		}
		round.mu.Unlock()
		time.Sleep(5 * time.Second)
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func handleClient(conn net.Conn, cfg config, round *roundState, registry *clientRegistry) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	firstLine, err := reader.ReadString('\n')
	if err != nil && firstLine == "" {
		return
	}
	trimmed := strings.TrimSpace(firstLine)

	// OmegaCases's own liveness probe: raw "PING" -> raw "PONG"
	if trimmed == "PING" {
		conn.Write([]byte("PONG"))
		return
	}

	var hello protocol.ClientMsg
	if err := json.Unmarshal([]byte(trimmed), &hello); err != nil || hello.Type != "hello" {
		log.Printf("[conn] rejected: expected hello, got: %s", trimmed)
		return
	}
	userID := hello.UserID
	idClean := strings.ReplaceAll(userID, "-", "")
	log.Printf("[conn] miner joined: %s", userID)

	c := &client{conn: conn}
	registry.add(c)
	defer registry.remove(c)

	round.mu.Lock()
	if round.previousHash != "" {
		c.send(protocol.ServerMsg{
			Type:         "job",
			PoolID:       cfg.poolID,
			PreviousHash: round.previousHash,
			Target:       round.shareTarget,
		})
	}
	round.mu.Unlock()

	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			var msg protocol.ClientMsg
			if jsonErr := json.Unmarshal([]byte(line), &msg); jsonErr != nil {
				log.Printf("[conn] bad message from %s: %v", userID, jsonErr)
			} else if msg.Type == "share" {
				handleShare(cfg, round, registry, userID, idClean, msg, c)
			}
		}
		if err != nil {
			break
		}
	}
	log.Printf("[conn] miner left: %s", userID)
}

func handleShare(cfg config, round *roundState, registry *clientRegistry, userID, idClean string, msg protocol.ClientMsg, c *client) {
	round.mu.Lock()
	expected := hashFor(round.previousHash, idClean, msg.Nonce)
	var accepted bool
	var message string
	var foundBlock bool
	var sharesSnapshot map[string]uint64

	switch {
	case expected != msg.Hash:
		accepted, message = false, "hash does not match nonce"
	case msg.Hash < round.shareTarget:
		round.shares[userID]++
		accepted = true
		message = fmt.Sprintf("share #%d", round.shares[userID])
		foundBlock = msg.Hash < round.networkTarget
		if foundBlock {
			sharesSnapshot = make(map[string]uint64, len(round.shares))
			for k, v := range round.shares {
				sharesSnapshot[k] = v
			}
		}
	default:
		accepted, message = false, "does not meet share target"
	}
	nonce, hash := msg.Nonce, msg.Hash
	round.mu.Unlock()

	c.send(protocol.ServerMsg{Type: "share_result", Accepted: accepted, Message: message})

	if foundBlock {
		log.Printf("[block] SOLVED by pool! nonce=%d hash=%s", nonce, hash)
		submitBlock(cfg, nonce, hash, sharesSnapshot)
	}
}

func main() {
	listen := flag.String("listen", "0.0.0.0:3333", "address to listen on for miners")
	poolID := flag.String("pool-id", "", "pool id returned when you registered the pool")
	apiKey := flag.String("api-key", "", "pool API key returned when you registered the pool")
	api := flag.String("api", "https://omegacases.com", "OmegaCases API base URL")
	shareFactor := flag.Int64("share-factor", 4096, "how much easier a share's target is than the real network target")
	flag.Parse()

	if *poolID == "" || *apiKey == "" {
		fmt.Println("Usage: oc-pool-server -pool-id <uuid> -api-key <key> [-listen 0.0.0.0:3333] [-api https://omegacases.com] [-share-factor 4096]")
		fmt.Println("Register a pool first: see /developer/docs/mining-pools")
		return
	}

	cfg := config{listen: *listen, poolID: *poolID, apiKey: *apiKey, api: *api, shareFactor: *shareFactor}
	log.Printf("OC pool server listening on %s (pool_id=%s api=%s)", cfg.listen, cfg.poolID, cfg.api)

	round := &roundState{shares: make(map[string]uint64)}
	registry := newClientRegistry()

	go watchBlocks(cfg, round, registry)

	listener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		log.Fatalf("failed to bind %s: %v", cfg.listen, err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleClient(conn, cfg, round, registry)
	}
}
