package signing

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode"
	"unicode/utf8"
)

const MaxOuterBytes = 32 << 20
const MaxJSONDepth = 64
const MaxJSONTokens = 200000

// ValidateSecurityJSON applies the outer bounds before mode selection. It
// neither authenticates nor interprets a statement.
func ValidateSecurityJSON(data []byte) error { return checkJSON(data, MaxOuterBytes) }

// checkJSON bounds work and detects duplicate keys before typed decoders can
// replace a critical value. Escaped equivalent keys are duplicates too.
func checkJSON(data []byte, maximum int) error {
	if len(data) == 0 || len(data) > maximum || !utf8.Valid(data) {
		return invalid("empty, oversized or non-UTF-8 security JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	tokens := 0
	if err := scanJSON(d, 0, &tokens); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return invalid("trailing or malformed security JSON")
	}
	return nil
}

func scanJSON(d *json.Decoder, depth int, tokens *int) error {
	if depth > MaxJSONDepth {
		return invalid("security JSON nesting exceeds 64 levels")
	}
	next := func() (json.Token, error) {
		*tokens++
		if *tokens > MaxJSONTokens {
			return nil, invalid("security JSON exceeds 200000 tokens")
		}
		value, err := d.Token()
		if err != nil {
			return nil, invalid("malformed security JSON")
		}
		return value, nil
	}
	t, err := next()
	if err != nil {
		return err
	}
	delim, composite := t.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			t, err := next()
			if err != nil {
				return err
			}
			key, ok := t.(string)
			if !ok || seen[key] {
				return invalid("duplicate or invalid security JSON key")
			}
			seen[key] = true
			if err := scanJSON(d, depth+1, tokens); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := scanJSON(d, depth+1, tokens); err != nil {
				return err
			}
		}
	default:
		return invalid("malformed security JSON")
	}
	closing, err := next()
	if err != nil || delim == '{' && closing != json.Delim('}') || delim == '[' && closing != json.Delim(']') {
		return invalid("malformed security JSON")
	}
	return nil
}

func fields(raw []byte, required []string, allowed ...string) (map[string]json.RawMessage, error) {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil || result == nil {
		return nil, invalid("expected a security JSON object")
	}
	for _, name := range required {
		if value, exists := result[name]; !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, invalid("missing or null required security field")
		}
	}
	for name := range result {
		found := false
		for _, exact := range allowed {
			if name == exact {
				found = true
				break
			}
		}
		if !found {
			return nil, invalid("unknown or noncanonical security field")
		}
	}
	return result, nil
}

func public(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
