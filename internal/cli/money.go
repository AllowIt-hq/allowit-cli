package cli

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// All money is exact: decimal strings are parsed into big.Rat and USDC is
// counted in integer micro-units, mirroring the server's validation.
var (
	usdcPattern     = regexp.MustCompile(`^(0|[1-9][0-9]{0,6})(\.[0-9]{1,6})?$`)
	quantityPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,6})(\.[0-9]{1,9})?$`)
	ratePattern     = regexp.MustCompile(`^(0|[1-9][0-9]{0,11})(\.[0-9]{1,18})?$`)
)

const maxUSDCUnits = 1_000_000_000_000

// defaultDecimals is used when the service does not publish asset precision.
var defaultDecimals = map[string]int{"SOL": 9, "XLM": 7, "USDC": 6}

// usdcUnits parses a positive USDC amount with at most six decimals.
func usdcUnits(v string) (*big.Int, error) {
	if !usdcPattern.MatchString(v) {
		return nil, fmt.Errorf("%q is not a USDC amount (positive decimal, at most 6 places, no exponent)", v)
	}
	n := decimalUnits(v, 6)
	if n.Sign() <= 0 || n.Cmp(big.NewInt(maxUSDCUnits)) > 0 {
		return nil, fmt.Errorf("%q must be greater than 0 and at most 1000000 USDC", v)
	}
	return n, nil
}

func decimalUnits(v string, places int) *big.Int {
	whole, frac, _ := strings.Cut(v, ".")
	n, _ := new(big.Int).SetString(whole+frac+strings.Repeat("0", places-len(frac)), 10)
	return n
}

func formatUnits(n *big.Int) string {
	s := n.String()
	if len(s) <= 6 {
		s = strings.Repeat("0", 7-len(s)) + s
	}
	whole, frac := s[:len(s)-6], strings.TrimRight(s[len(s)-6:], "0")
	if frac == "" {
		return whole
	}
	return whole + "." + frac
}

// budgetCharge returns the exact USDC amount the server requires for a mock
// plan: the transfer value rounded up to one micro-USDC, plus every call's
// maxCostUSDC.
func budgetCharge(quantity, rate string, decimals int, calls []Call) (string, error) {
	if !quantityPattern.MatchString(quantity) {
		return "", fmt.Errorf("%q is not a quantity (positive decimal, no exponent)", quantity)
	}
	if _, frac, ok := strings.Cut(quantity, "."); ok && len(frac) > decimals {
		return "", fmt.Errorf("%q has more than %d decimal places for this asset", quantity, decimals)
	}
	if !ratePattern.MatchString(rate) {
		return "", errors.New("the service published an invalid rate")
	}
	qty, _ := new(big.Rat).SetString(quantity)
	if qty.Sign() <= 0 {
		return "", errors.New("quantity must be greater than 0")
	}
	price, _ := new(big.Rat).SetString(rate)
	value := new(big.Rat).Mul(qty, price)
	value.Mul(value, big.NewRat(1_000_000, 1))
	cost, rem := new(big.Int).QuoRem(value.Num(), value.Denom(), new(big.Int))
	if rem.Sign() > 0 {
		cost.Add(cost, big.NewInt(1))
	}
	for i, call := range calls {
		if call.MaxCost == "0" {
			continue
		}
		n, err := usdcUnits(call.MaxCost)
		if err != nil {
			return "", fmt.Errorf("call %d maxCostUSDC: %v", i, err)
		}
		cost.Add(cost, n)
	}
	if cost.Sign() <= 0 || cost.Cmp(big.NewInt(maxUSDCUnits)) > 0 {
		return "", errors.New("the budget charge must be greater than 0 and at most 1000000 USDC")
	}
	return formatUnits(cost), nil
}
