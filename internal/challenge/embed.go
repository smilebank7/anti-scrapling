package challenge

import _ "embed"

//go:embed assets/index.html
var ChallengeHTML []byte

//go:embed assets/challenge.bundle.js
var ChallengeBundle []byte
