//go:build tools

package tools

import (
	_ "github.com/google/cel-go/cel"
	_ "github.com/google/uuid"
	_ "github.com/hashicorp/golang-lru/v2"
	_ "github.com/oschwald/maxminddb-golang"
	_ "github.com/prometheus/client_golang/prometheus"
	_ "github.com/redis/go-redis/v9"
	_ "github.com/refraction-networking/utls"
	_ "github.com/spf13/cobra"
	_ "github.com/stretchr/testify/assert"
	_ "gopkg.in/yaml.v3"
)
