package challenge

import (
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
)

const challengeTTL = 10 * time.Minute

type ChallengeIssuer struct {
	powDifficulty int
	ids           *lru.Cache[string, time.Time]
}

func NewChallengeIssuer(powDifficulty int) (*ChallengeIssuer, error) {
	cache, err := lru.New[string, time.Time](4096)
	if err != nil {
		return nil, err
	}
	return &ChallengeIssuer{powDifficulty: powDifficulty, ids: cache}, nil
}

func (ci *ChallengeIssuer) NewChallengeID() string {
	id := uuid.NewString()
	ci.ids.Add(id, time.Now())
	return id
}

func (ci *ChallengeIssuer) ValidateChallengeID(id string) bool {
	issued, ok := ci.ids.Get(id)
	if !ok {
		return false
	}
	if time.Since(issued) > challengeTTL {
		ci.ids.Remove(id)
		return false
	}
	ci.ids.Remove(id)
	return true
}
