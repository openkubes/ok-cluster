// Package jsonstrict decodes security-relevant JSON without accepting duplicate
// object keys, trailing values, or unknown fields.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Decode validates raw JSON and decodes it into target.
func Decode(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeValue(decoder, "$", nil); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("$: trailing JSON token %v", token)
		}
		return fmt.Errorf("$: trailing JSON: %w", err)
	}

	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	typed.UseNumber()
	if err := typed.Decode(target); err != nil {
		return err
	}
	if err := requireEOF(typed); err != nil {
		return err
	}
	return nil
}

func consumeValue(decoder *json.Decoder, path string, first json.Token) error {
	token := first
	var err error
	if token == nil {
		token, err = decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%s: object key is not a string", path)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("%s: duplicate object key %q", path, key)
			}
			seen[key] = struct{}{}
			if err := consumeValue(decoder, path+"."+key, nil); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("%s: malformed object", path)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := consumeValue(decoder, fmt.Sprintf("%s[%d]", path, index), nil); err != nil {
				return err
			}
			index++
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("%s: malformed array", path)
		}
	default:
		return fmt.Errorf("%s: unexpected delimiter %q", path, delimiter)
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
