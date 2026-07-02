[![OmegaCases](https://hebbkx1anhila5yf.public.blob.vercel-storage.com/omegacrate_logo-tJzRwAfwpZAQEkJOSjQGI93l5hRU06.png)OmegaCases](/)Cases[Marketplace](/marketplace)[Trade](/trade)[Mining](/mining)[Chat](/chat)[Leaderboard](/leaderboard) [Plus](/plus)

[Developer](/developer)

Docs

[Overview](/developer/docs/overview)[OAuth](/developer/docs/oauth)[Tokens](/developer/docs/tokens)[Spend Balance](/developer/docs/spend)[Open Cases](/developer/docs/cases)[Buy Listings](/developer/docs/listings)[Notifications](/developer/docs/notify)[Public API](/developer/docs/public)[Mining Pools](/developer/docs/mining-pools)

# Creating your own OmegaCases Mining Pool

A mining pool lets many miners combine hashpower and split OmegaZites rewards proportionally to the shares they contribute. You do not need much custom code to run one. OmegaCases handles listing, uptime checks, the join flow, and splitting the reward, all automatically.

What you actually need to build

Only two things are required from you as the pool operator.

1. Answer PING with PONGSomething listening on the port you register, that replies with the text PONG when it receives PING. This can be a few lines in almost any language.

2. Accept miners and report blocksYour own logic for accepting miner connections, tracking their shares (PPLNS, proportional, or anything you like), and calling the submit-block endpoint whenever you solve a block.

Everything else, listing your pool publicly, checking that it is still online, letting users join, and splitting the OmegaZites reward across participants, is handled by OmegaCases for you.

**You do not have to design this protocol yourself.** The official miner at `github.com/harsiz/oc-miner` already ships a working reference pool server, `oc-pool-server`, that implements a small, documented protocol (the OC-Miner Pool Protocol v1, newline-delimited JSON) and already answers PING with PONG and calls submit-block for you. Most operators can just run `oc-pool-server -listen 0.0.0.0:PORT -pool-id ID -api-key KEY` instead of writing anything. The miner itself already supports pointing at any pool speaking this protocol, so members can mine to your pool immediately, no custom client needed either. Build your own server only if you want different payout logic or a different wire protocol.

## Prerequisites

You need a VPS or a machine you control (even a home computer works) with a public IPv4 or IPv6 address and an open port that miners and OmegaCases can reach. You can create an unlimited number of pools.

POST /api/mining/pools (register a pool)

Request

```
fetch("https://omegacases.com/api/mining/pools", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    owner_id:    "your-user-id",
    name:        "My Pool",
    host:        "203.0.113.10",
    port:        3333,
    ip_version:  "auto",       // "ipv4", "ipv6", or "auto"
    description: "Low fee pool, PPLNS payouts"
  })
})
```

Response

```
{
  "success": true,
  "pool":    { "id": "pool-uuid", "status": "testing", ... },
  "api_key": "a3f9c2...",
  "warning": "Save this API key now, it will not be shown again."
}
```

**Save the api\_key immediately.** It is shown once and is required to authenticate every future call your pool makes to OmegaCases.

## Authenticating pool API calls

Calls your pool makes to OmegaCases (like submitting a found block) are authenticated with your API key, not a normal user session, since your pool is an unattended server rather than a logged in browser. Send it as a bearer token.

Authorization header

```
Authorization: Bearer a3f9c2...
```

## The 30 second liveness check

After you register, OmegaCases's own server starts connecting to the host and port you gave it. It sends a short message, `PING`, and expects `PONG` back. This repeats for about 30 seconds. If enough of those checks succeed, your pool's status changes from`testing` to `active` and it appears on the public pool list at`/mining`. If it fails, your pool goes back to `pending` and you can fix whatever is blocking the connection (a firewall rule, for example) and try again by editing the pool, which restarts the check.

## Ongoing uptime checks

OmegaCases keeps re-checking active pools the same way, roughly every few minutes, for as long as you are listed. A pool that stops answering PING for several checks in a row gets marked offline until it responds again. You do not need to call anything yourself for this, OmegaCases always initiates the check.

POST /api/mining/pools/{id}/submit-block (report a found block)

Call this when your pool solves a block. Include the winning nonce and hash, plus the shares each participant contributed for that round.

Request

```
fetch("https://omegacases.com/api/mining/pools/{id}/submit-block", {
  method: "POST",
  headers: {
    "Content-Type":  "application/json",
    "Authorization": "Bearer a3f9c2..."
  },
  body: JSON.stringify({
    nonce: 918234,
    hash:  "0000abc...",
    shares: [
      { "user_id": "uuid-of-participant",       "shares": 1500 },
      { "user_id": "uuid-of-another-participant", "shares": 800 }
    ]
  })
})
```

Response

```
{
  "success": true,
  "block":   { "height": 1234, "reward_zites": 64 },
  "payouts": [
    { "user_id": "...", "shares": 1500, "zites_credited": 41.7391 },
    { "user_id": "...", "shares": 800,  "zites_credited": 22.2609 }
  ]
}
```

The proof of work preimage for a pool block is `previous_hash + pool_id_no_dashes + nonce`, using your pool's own id in place of an individual miner's id, since many people contribute to one pool block. This differs from solo mining, where the miner's own user id is used instead.

Any `user_id` in the shares list that has not joined your pool through the site first is ignored. Users join from your pool's page by pressing Join Pool.

## PPLNS and payout logic is your responsibility

OmegaCases does not care how you decide share weights internally, whether that is PPLNS, PPS, simple proportional, or anything else. It only takes the shares list you submit at block-found time and splits that block's OmegaZites reward proportionally among those numbers. All internal accounting, minimum payout thresholds, and fairness between your own miners is entirely up to you.

## Getting listed and letting users join

Once active, your pool appears on `/mining` showing its uptime, blocks found, and member count so prospective miners can evaluate it before joining. When a user presses Join Pool, OmegaCases simply records them as a participant, so the site can show that they are a member and so your `submit-block` calls can credit their `user_id`. The user still needs to separately configure their own mining software with your pool's host and port to actually start contributing hashpower, joining on the site does not connect them to your server for you.

## Endpoints at a glance

POST

`/api/mining/pools`

Register a new pool, returns a one time API key

GET

`/api/mining/pools`

Public list of active pools

GET

`/api/mining/pools/{id}`

Pool detail, stats, and recent blocks

PATCH

`/api/mining/pools/{id}`

Owner edits, host or port changes re-run the liveness check

POST

`/api/mining/pools/{id}/join`

Join a pool as a declared participant

DELETE

`/api/mining/pools/{id}/join`

Leave a pool

POST

`/api/mining/pools/{id}/submit-block`

Report a found block and the shares to split its reward

Treat your pool's API key like a password. Anyone with it can submit blocks and shares on your pool's behalf.

Live Rolls0

No rolls yet — open some cases!

Live

No rolls yet
