package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/token"
	"github.com/spf13/cobra"
)

func newTokenCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "token",
		Short: "JWT token issuance and verification",
	}
	c.AddCommand(newTokenIssueCmd(), newTokenVerifyCmd())
	return c
}

func newTokenIssueCmd() *cobra.Command {
	var bindStr, keyFile, ttlStr string

	c := &cobra.Command{
		Use:   "issue",
		Short: "Issue a JWT pass-token",
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := token.LoadKey(keyFile)
			if err != nil {
				return err
			}

			ttl, err := time.ParseDuration(ttlStr)
			if err != nil {
				return fmt.Errorf("invalid --ttl %q: %w", ttlStr, err)
			}

			bindings, ctx, err := parseBindings(bindStr)
			if err != nil {
				return err
			}

			issuer := token.NewIssuer(key, ttl, bindings)
			tok, err := issuer.Issue(ctx)
			if err != nil {
				return err
			}

			fmt.Fprintln(cmd.OutOrStdout(), tok)
			return nil
		},
	}

	c.Flags().StringVar(&bindStr, "bind", "", "Comma-separated key=value bindings: ip=1.2.3.4,ua=Mozilla,ja3=...")
	c.Flags().StringVar(&ttlStr, "ttl", "24h", "Token TTL (e.g. 24h, 30m)")
	c.Flags().StringVar(&keyFile, "key", "token.key", "Path to HMAC key file")
	_ = c.MarkFlagRequired("key")
	return c
}

func newTokenVerifyCmd() *cobra.Command {
	var bindStr, keyFile string

	c := &cobra.Command{
		Use:   "verify <token>",
		Short: "Parse and verify a JWT pass-token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := token.LoadKey(keyFile)
			if err != nil {
				return err
			}

			bindings, issueCtx, err := parseBindings(bindStr)
			if err != nil {
				return err
			}

			verifier := token.NewVerifier(key, bindings)
			claims, err := verifier.Verify(args[0], token.VerifyContext{
				IP:  issueCtx.IP,
				UA:  issueCtx.UA,
				JA3: issueCtx.JA3,
				JA4: issueCtx.JA4,
			})
			if err != nil {
				return err
			}

			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(claims)
		},
	}

	c.Flags().StringVar(&bindStr, "bind", "", "Comma-separated key=value bindings to verify against")
	c.Flags().StringVar(&keyFile, "key", "token.key", "Path to HMAC key file")
	_ = c.MarkFlagRequired("key")
	return c
}

func parseBindings(bindStr string) ([]string, token.IssueContext, error) {
	var ctx token.IssueContext
	var bindings []string

	if bindStr == "" {
		return bindings, ctx, nil
	}

	for _, pair := range strings.Split(bindStr, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, ctx, fmt.Errorf("invalid binding %q: expected key=value", pair)
		}
		bindings = append(bindings, k)
		switch k {
		case "ip":
			ctx.IP = v
		case "ua":
			ctx.UA = v
		case "ja3":
			ctx.JA3 = v
		case "ja4":
			ctx.JA4 = v
		default:
			return nil, ctx, fmt.Errorf("unknown binding key %q (valid: ip, ua, ja3, ja4)", k)
		}
	}
	return bindings, ctx, nil
}
