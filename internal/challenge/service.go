package challenge

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/bits"
	"net"
	"net/http"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/signal/fingerprint"
	"github.com/smilebank7/anti-scrapling/internal/token"
	"github.com/smilebank7/anti-scrapling/internal/types"
)

const metaPlaceholder = `<meta name="__as_challenge" content='{"challenge_id":"","difficulty":0,"beacon_interval_ms":5000}'>`

type BeaconIngestor interface {
	Ingest(beacon types.BehaviorBeacon) error
}

type beaconIngestorWithRequest interface {
	BeaconIngestor
	IngestFromRequest(r *http.Request, beacon types.BehaviorBeacon) error
}

type Service struct {
	issuer        *ChallengeIssuer
	tokenIssuer   *token.Issuer
	denyThreshold int
	cookieTTL     time.Duration
	beacon        BeaconIngestor
}

func NewService(issuer *ChallengeIssuer, tokenIssuer *token.Issuer, denyThreshold int, cookieTTL time.Duration, beacon BeaconIngestor) *Service {
	return &Service{
		issuer:        issuer,
		tokenIssuer:   tokenIssuer,
		denyThreshold: denyThreshold,
		cookieTTL:     cookieTTL,
		beacon:        beacon,
	}
}

func (s *Service) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	id := s.issuer.NewChallengeID()
	origin := r.URL.Query().Get("origin")
	if origin == "" {
		origin = "/"
	}

	meta := fmt.Sprintf(`<meta name="__as_challenge" data-id="%s" data-difficulty="%d" data-origin="%s">`,
		id, s.issuer.powDifficulty, origin)

	html := bytes.ReplaceAll(ChallengeHTML, []byte(metaPlaceholder), []byte(meta))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(html)
}

func (s *Service) HandleBundle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.WriteHeader(http.StatusOK)
	w.Write(ChallengeBundle)
}

type verifyRequest struct {
	PowSolution       string                  `json:"pow_solution"`
	FingerprintReport types.FingerprintReport `json:"fingerprint_report"`
	ChallengeID       string                  `json:"challenge_id"`
	OriginURL         string                  `json:"origin_url"`
}

func (s *Service) HandleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if !s.issuer.ValidateChallengeID(req.ChallengeID) {
		http.Error(w, "invalid or expired challenge_id", http.StatusBadRequest)
		return
	}

	if !verifyPoW(req.ChallengeID, req.PowSolution, s.issuer.powDifficulty) {
		http.Error(w, "invalid proof of work", http.StatusBadRequest)
		return
	}

	signals, err := fingerprint.Score(req.FingerprintReport)
	if err != nil {
		http.Error(w, "fingerprint scoring error", http.StatusInternalServerError)
		return
	}

	total := 0
	reasons := make([]string, 0, len(signals))
	for _, sig := range signals {
		total += sig.Score
		if sig.Score > 0 {
			reasons = append(reasons, sig.Reason)
		}
	}

	if total >= s.denyThreshold {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "fingerprint score too high",
			"score":   total,
			"reasons": reasons,
		})
		return
	}

	// Extract IP and User-Agent for token binding.
	// JA3/JA4 are not available here because the challenge page is served over
	// plain HTTP after the initial TLS redirect; the ClientHello capture lives
	// on the proxy connection and is not propagated into the challenge sub-request.
	// TODO(v0.2): propagate JA3/JA4 via a signed cookie set at the proxy layer.
	clientIP, _, ipErr := net.SplitHostPort(r.RemoteAddr)
	if ipErr != nil {
		clientIP = r.RemoteAddr
	}
	clientUA := r.Header.Get("User-Agent")

	tok, err := s.tokenIssuer.Issue(token.IssueContext{
		FingerprintHash: req.ChallengeID,
		Score:           total,
		IP:              clientIP,
		UA:              clientUA,
	})
	if err != nil {
		http.Error(w, "token issuance failed", http.StatusInternalServerError)
		return
	}

	token.SetCookie(w, token.DefaultCookieName, tok, s.cookieTTL, false)

	target := req.OriginURL
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Service) HandleBeacon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var b types.BehaviorBeacon
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if s.beacon != nil {
		if full, ok := s.beacon.(beaconIngestorWithRequest); ok {
			full.IngestFromRequest(r, b)
		} else {
			s.beacon.Ingest(b)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) HandleSW(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("self.addEventListener('fetch',()=>{});"))
}

func verifyPoW(challengeID, solution string, difficulty int) bool {
	sum := sha256.Sum256([]byte(challengeID + solution))
	return leadingZeroBits(sum[:]) >= difficulty
}

func leadingZeroBits(b []byte) int {
	total := 0
	for _, byt := range b {
		z := bits.LeadingZeros8(byt)
		total += z
		if z < 8 {
			break
		}
	}
	return total
}
