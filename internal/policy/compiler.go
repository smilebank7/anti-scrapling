package policy

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	itypes "github.com/smilebank7/anti-scrapling/internal/types"
)

var (
	sharedEnv     *cel.Env
	sharedEnvOnce sync.Once
	sharedEnvErr  error
)

func getEnv() (*cel.Env, error) {
	sharedEnvOnce.Do(func() {
		sharedEnv, sharedEnvErr = buildEnv()
	})
	return sharedEnv, sharedEnvErr
}

func buildEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("ip", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("ja3", cel.StringType),
		cel.Variable("ja4", cel.StringType),
		cel.Variable("score", cel.IntType),
		cel.Variable("has_valid_token", cel.BoolType),
		cel.Variable("signals", cel.MapType(cel.StringType, cel.IntType)),
		cel.Function(
			"matches_family",
			cel.MemberOverload(
				"string_matches_family_list",
				[]*cel.Type{cel.StringType, cel.ListType(cel.StringType)},
				cel.BoolType,
				cel.BinaryBinding(matchesFamilyBinding),
			),
		),
	)
}

func matchesFamilyBinding(lhs, rhs ref.Val) ref.Val {
	ja3Str, ok := lhs.Value().(string)
	if !ok {
		return celtypes.Bool(false)
	}

	listVal, ok := rhs.(traits.Lister)
	if !ok {
		return celtypes.Bool(false)
	}

	it := listVal.Iterator()
	for it.HasNext() == celtypes.True {
		pattern, ok := it.Next().Value().(string)
		if !ok {
			continue
		}
		cleanPattern := strings.TrimPrefix(pattern, "@")
		matched, err := path.Match(cleanPattern, ja3Str)
		if err == nil && matched {
			return celtypes.Bool(true)
		}
	}

	return celtypes.Bool(false)
}

// CompiledRule pairs a policy rule with its compiled CEL program.
type CompiledRule struct {
	Rule    *itypes.PolicyRule
	Program cel.Program
}

func compileRule(rule *itypes.PolicyRule) (*CompiledRule, error) {
	env, err := getEnv()
	if err != nil {
		return nil, fmt.Errorf("CEL env: %w", err)
	}

	expr, err := matchMapToExpr(rule.Match)
	if err != nil {
		return nil, fmt.Errorf("match expression: %w", err)
	}

	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("CEL compile %q: %w", expr, issues.Err())
	}

	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("CEL program: %w", err)
	}

	return &CompiledRule{Rule: rule, Program: prg}, nil
}

func matchMapToExpr(match map[string]any) (string, error) {
	if len(match) == 0 {
		return "true", nil
	}

	keys := make([]string, 0, len(match))
	for k := range match {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		part, err := keyValueToExpr(key, match[key])
		if err != nil {
			return "", err
		}
		parts = append(parts, part)
	}

	return strings.Join(parts, " && "), nil
}

func keyValueToExpr(key string, value any) (string, error) {
	switch key {
	case "expr":
		s, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("\"expr\" value must be a string, got %T", value)
		}
		return s, nil

	case "path":
		s, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("\"path\" value must be a string, got %T", value)
		}
		return fmt.Sprintf("request.path == %q", s), nil

	case "path_prefix":
		s, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("\"path_prefix\" value must be a string, got %T", value)
		}
		return fmt.Sprintf("request.path.startsWith(%q)", s), nil

	case "ja3_in":
		list, err := toStringSlice(value)
		if err != nil {
			return "", fmt.Errorf("\"ja3_in\" value: %w", err)
		}
		return fmt.Sprintf("ja3.matches_family([%s])", joinQuoted(list)), nil

	case "score":
		s, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("\"score\" value must be a quoted comparison string like \">=50\", got %T", value)
		}
		return parseScoreExpr(s)

	case "ip_category":
		s, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("\"ip_category\" value must be a string, got %T", value)
		}
		return fmt.Sprintf("ip.category == %q", s), nil

	case "has_valid_token":
		b, ok := value.(bool)
		if !ok {
			return "", fmt.Errorf("\"has_valid_token\" value must be a bool, got %T", value)
		}
		if b {
			return "has_valid_token", nil
		}
		return "!has_valid_token", nil

	default:
		return "", fmt.Errorf("unknown match key %q", key)
	}
}

var comparisonOps = []string{">=", "<=", "!=", ">", "<", "=="}

func parseScoreExpr(s string) (string, error) {
	for _, op := range comparisonOps {
		if strings.HasPrefix(s, op) {
			numStr := strings.TrimSpace(s[len(op):])
			if _, err := strconv.Atoi(numStr); err != nil {
				return "", fmt.Errorf("invalid number in score comparison %q: %w", s, err)
			}
			return fmt.Sprintf("score %s %s", op, numStr), nil
		}
	}
	return "", fmt.Errorf("invalid score comparison %q: must start with an operator (>=, <=, !=, >, <, ==)", s)
}

func toStringSlice(value any) ([]string, error) {
	raw, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a list, got %T", value)
	}
	result := make([]string, 0, len(raw))
	for i, v := range raw {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("element %d is not a string, got %T", i, v)
		}
		result = append(result, s)
	}
	return result, nil
}

func joinQuoted(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(parts, ", ")
}
