// Package contract implements the deterministic, side-effect-free part of the
// OpenKubes Contract Executor. It deliberately knows nothing about Kubernetes
// clients, credentials, submission, or reconciliation.
package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const CanonicalizationProfile = "openkubes-contract-c14n/v1"

// Result is the immutable identity produced from a raw contract and its test
// schema. CanonicalJSON contains semantic fields only.
type Result struct {
	CanonicalizationProfile string
	RawArtifactDigest       string
	SchemaDigest            string
	NormalizedDigest        string
	CanonicalJSON           []byte
	Normalized              any
}

// Identity is the stable contract identity needed by a typed operation.
type Identity struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// Canonicalize parses a single YAML or JSON document, validates and normalizes
// it with the versioned schema subset used by OK-141, removes fields explicitly
// declared non-semantic, and hashes canonical JSON.
func Canonicalize(raw, schemaRaw []byte) (Result, error) {
	schema, err := parseJSON(schemaRaw)
	if err != nil {
		return Result{}, fmt.Errorf("parse schema: %w", err)
	}
	source, err := parseYAML(raw)
	if err != nil {
		return Result{}, fmt.Errorf("parse contract: %w", err)
	}
	normalized, err := normalize(source, schema, "$")
	if err != nil {
		return Result{}, err
	}
	if err := validateClusterSemantics(normalized); err != nil {
		return Result{}, err
	}
	semantic, included, err := semanticProjection(normalized, schema)
	if err != nil {
		return Result{}, err
	}
	if !included {
		return Result{}, errors.New("$: entire contract is declared non-semantic")
	}
	canonical, err := JCS(semantic)
	if err != nil {
		return Result{}, fmt.Errorf("canonical JSON: %w", err)
	}
	return Result{
		CanonicalizationProfile: CanonicalizationProfile,
		RawArtifactDigest:       digest(raw),
		SchemaDigest:            digest(schemaRaw),
		NormalizedDigest:        digest(canonical),
		CanonicalJSON:           canonical,
		Normalized:              normalized,
	}, nil
}

// ContractIdentity extracts the stable name and namespace after validation.
func ContractIdentity(normalized any) (Identity, error) {
	root, ok := normalized.(map[string]any)
	if !ok {
		return Identity{}, errors.New("$: normalized contract is not an object")
	}
	metadata, ok := root["metadata"].(map[string]any)
	if !ok {
		return Identity{}, errors.New("$.metadata: normalized metadata is not an object")
	}
	name, nameOK := metadata["name"].(string)
	namespace, namespaceOK := metadata["namespace"].(string)
	if !nameOK || name == "" || !namespaceOK || namespace == "" {
		return Identity{}, errors.New("$.metadata: name and namespace are required")
	}
	return Identity{Namespace: namespace, Name: name}, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func parseJSON(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	return value, nil
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

func parseYAML(raw []byte) (any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if len(document.Content) != 1 {
		return nil, errors.New("exactly one YAML document is required")
	}
	if err := validateYAMLNode(document.Content[0], "$"); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil && len(extra.Content) > 0 {
			return nil, errors.New("multiple YAML documents are not allowed")
		}
		if err != nil {
			return nil, err
		}
	}
	var value any
	if err := document.Content[0].Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func validateYAMLNode(node *yaml.Node, path string) error {
	switch node.Kind {
	case yaml.AliasNode:
		return fmt.Errorf("%s: YAML aliases are not allowed", path)
	case yaml.MappingNode:
		seen := map[string]struct{}{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("%s: all object keys must be strings", path)
			}
			if _, exists := seen[key.Value]; exists {
				return fmt.Errorf("%s: duplicate mapping key %q", path, key.Value)
			}
			seen[key.Value] = struct{}{}
			if err := validateYAMLNode(node.Content[index+1], path+"."+key.Value); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for index, child := range node.Content {
			if err := validateYAMLNode(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalize(value any, schema map[string]any, path string) (any, error) {
	expected, _ := schema["type"].(string)
	if expected != "" && !typeMatches(value, expected) {
		return nil, fmt.Errorf("%s: expected %s, got %T", path, expected, value)
	}
	if constant, exists := schema["const"]; exists {
		equal, err := canonicalEqual(value, constant)
		if err != nil || !equal {
			return nil, fmt.Errorf("%s: value differs from the declared constant", path)
		}
	}
	if values, ok := schema["enum"].([]any); ok {
		matched := false
		for _, candidate := range values {
			equal, err := canonicalEqual(value, candidate)
			if err == nil && equal {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("%s: value is not in the declared enum", path)
		}
	}

	switch expected {
	case "object":
		object := value.(map[string]any)
		properties, _ := schema["properties"].(map[string]any)
		additional, hasAdditional := schema["additionalProperties"].(bool)
		if !hasAdditional {
			additional = true
		}
		if !additional {
			var unknown []string
			for key := range object {
				if _, exists := properties[key]; !exists {
					unknown = append(unknown, key)
				}
			}
			sort.Strings(unknown)
			if len(unknown) > 0 {
				return nil, fmt.Errorf("%s: unknown fields: %s", path, strings.Join(unknown, ", "))
			}
		}
		required := stringSet(schema["required"])
		result := make(map[string]any, len(object))
		for name, rawChildSchema := range properties {
			childSchema, ok := rawChildSchema.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s.%s: invalid schema", path, name)
			}
			child, exists := object[name]
			if !exists {
				if defaultValue, hasDefault := childSchema["default"]; hasDefault {
					child = defaultValue
					exists = true
				} else if _, isRequired := required[name]; isRequired {
					return nil, fmt.Errorf("%s.%s: required field is missing", path, name)
				}
			}
			if exists {
				normalized, err := normalize(child, childSchema, path+"."+name)
				if err != nil {
					return nil, err
				}
				result[name] = normalized
			}
		}
		if additional {
			for name, child := range object {
				if _, declared := properties[name]; !declared {
					result[name] = child
				}
			}
		}
		return result, nil
	case "array":
		itemsSchema, ok := schema["items"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: array schema has no items schema", path)
		}
		input := value.([]any)
		result := make([]any, 0, len(input))
		unique := map[string]struct{}{}
		for index, item := range input {
			normalized, err := normalize(item, itemsSchema, fmt.Sprintf("%s[%d]", path, index))
			if err != nil {
				return nil, err
			}
			if schema["uniqueItems"] == true {
				encoded, err := JCS(normalized)
				if err != nil {
					return nil, err
				}
				key := string(encoded)
				if _, exists := unique[key]; exists {
					return nil, fmt.Errorf("%s: array items must be unique", path)
				}
				unique[key] = struct{}{}
			}
			result = append(result, normalized)
		}
		if minimum, ok := schemaInteger(schema["minItems"]); ok && int64(len(result)) < minimum {
			return nil, fmt.Errorf("%s: requires at least %d items", path, minimum)
		}
		if maximum, ok := schemaInteger(schema["maxItems"]); ok && int64(len(result)) > maximum {
			return nil, fmt.Errorf("%s: allows at most %d items", path, maximum)
		}
		return result, nil
	case "string":
		text := value.(string)
		if minimum, ok := schemaInteger(schema["minLength"]); ok && int64(utf8.RuneCountInString(text)) < minimum {
			return nil, fmt.Errorf("%s: string is shorter than %d", path, minimum)
		}
		if pattern, ok := schema["pattern"].(string); ok {
			expression, err := regexp.Compile("^(?:" + pattern + ")$")
			if err != nil {
				return nil, fmt.Errorf("%s: invalid schema pattern: %w", path, err)
			}
			if !expression.MatchString(text) {
				return nil, fmt.Errorf("%s: string does not match the declared pattern", path)
			}
		}
		switch schema["format"] {
		case "sha256":
			if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(text) {
				return nil, fmt.Errorf("%s: expected sha256:<64 lowercase hex>", path)
			}
		case "ipv4-cidr":
			prefix, err := netip.ParsePrefix(text)
			if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || prefix.String() != text {
				return nil, fmt.Errorf("%s: invalid canonical IPv4 CIDR", path)
			}
		}
		return text, nil
	case "integer":
		integer, ok := integerValue(value)
		if !ok {
			return nil, fmt.Errorf("%s: expected integer", path)
		}
		if minimum, ok := schemaInteger(schema["minimum"]); ok && integer < minimum {
			return nil, fmt.Errorf("%s: integer must be >= %d", path, minimum)
		}
		return integer, nil
	case "boolean", "null":
		return value, nil
	case "":
		return value, nil
	default:
		return nil, fmt.Errorf("%s: unsupported schema type %q", path, expected)
	}
}

func typeMatches(value any, expected string) bool {
	switch expected {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "integer":
		_, ok := integerValue(value)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	default:
		return false
	}
}

func integerValue(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int8:
		return int64(number), true
	case int16:
		return int64(number), true
	case int32:
		return int64(number), true
	case int64:
		return number, true
	case uint:
		if uint64(number) > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(number), true
	case uint8:
		return int64(number), true
	case uint16:
		return int64(number), true
	case uint32:
		return int64(number), true
	case uint64:
		if number > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(number), true
	case json.Number:
		integer, err := number.Int64()
		return integer, err == nil
	default:
		return 0, false
	}
}

func schemaInteger(value any) (int64, bool) {
	if value == nil {
		return 0, false
	}
	return integerValue(value)
}

func stringSet(value any) map[string]struct{} {
	result := map[string]struct{}{}
	items, _ := value.([]any)
	for _, item := range items {
		if text, ok := item.(string); ok {
			result[text] = struct{}{}
		}
	}
	return result
}

func canonicalEqual(left, right any) (bool, error) {
	leftJSON, err := JCS(left)
	if err != nil {
		return false, err
	}
	rightJSON, err := JCS(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(leftJSON, rightJSON), nil
}

func semanticProjection(value any, schema map[string]any) (any, bool, error) {
	if semantic, exists := schema["x-openkubes-semantic"].(bool); exists && !semantic {
		return nil, false, nil
	}
	switch schema["type"] {
	case "object":
		object := value.(map[string]any)
		properties, _ := schema["properties"].(map[string]any)
		result := map[string]any{}
		for name, child := range object {
			childSchema, declared := properties[name].(map[string]any)
			if !declared {
				result[name] = child
				continue
			}
			projected, include, err := semanticProjection(child, childSchema)
			if err != nil {
				return nil, false, err
			}
			if include {
				result[name] = projected
			}
		}
		return result, true, nil
	case "array":
		itemsSchema, ok := schema["items"].(map[string]any)
		if !ok {
			return nil, false, errors.New("array schema has no items schema")
		}
		items := value.([]any)
		result := make([]any, 0, len(items))
		for _, item := range items {
			projected, include, err := semanticProjection(item, itemsSchema)
			if err != nil {
				return nil, false, err
			}
			if include {
				result = append(result, projected)
			}
		}
		return result, true, nil
	default:
		return value, true, nil
	}
}

func validateClusterSemantics(value any) error {
	root, ok := value.(map[string]any)
	if !ok {
		return errors.New("$: expected contract object")
	}
	spec, ok := root["spec"].(map[string]any)
	if !ok {
		return errors.New("$.spec: expected object")
	}
	connectivity, ok := spec["connectivity"].(map[string]any)
	if !ok {
		return errors.New("$.spec.connectivity: expected object")
	}
	pod, err := netip.ParsePrefix(connectivity["podCIDR"].(string))
	if err != nil {
		return fmt.Errorf("$.spec.connectivity.podCIDR: %w", err)
	}
	service, err := netip.ParsePrefix(connectivity["serviceCIDR"].(string))
	if err != nil {
		return fmt.Errorf("$.spec.connectivity.serviceCIDR: %w", err)
	}
	if connectivity["profile"] == "datacenter-isolated-v1" {
		if pod.Bits() != 16 {
			return errors.New("$.spec.connectivity.podCIDR: profile requires /16")
		}
		if service.Bits() != 20 {
			return errors.New("$.spec.connectivity.serviceCIDR: profile requires /20")
		}
	}
	if pod.Overlaps(service) {
		return errors.New("Pod and Service CIDRs must not overlap")
	}
	for _, raw := range connectivity["forbiddenCIDRs"].([]any) {
		forbidden, err := netip.ParsePrefix(raw.(string))
		if err != nil {
			return err
		}
		if pod.Overlaps(forbidden) || service.Overlaps(forbidden) {
			return fmt.Errorf("Cluster CIDR overlaps forbidden range %s", forbidden)
		}
	}
	return nil
}

// JCS encodes the no-float JSON subset used by the versioned OK-141 profile.
// Object keys are ordered by UTF-16 code units, matching RFC 8785.
func JCS(value any) ([]byte, error) {
	var output bytes.Buffer
	if err := appendJCS(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func appendJCS(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		output.WriteString(strconv.FormatBool(typed))
	case string:
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(typed); err != nil {
			return err
		}
		output.Write(bytes.TrimSuffix(encoded.Bytes(), []byte("\n")))
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(left, right int) bool {
			return utf16Less(keys[left], keys[right])
		})
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := appendJCS(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := appendJCS(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := appendJCS(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	default:
		integer, ok := integerValue(value)
		if !ok {
			return fmt.Errorf("unsupported canonical JSON type %T", value)
		}
		output.WriteString(strconv.FormatInt(integer, 10))
	}
	return nil
}

func utf16Less(left, right string) bool {
	a := utf16.Encode([]rune(left))
	b := utf16.Encode([]rune(right))
	for index := 0; index < len(a) && index < len(b); index++ {
		if a[index] != b[index] {
			return a[index] < b[index]
		}
	}
	return len(a) < len(b)
}

// EqualNormalized is useful to prove equivalence without exposing internal
// normalized representations to callers.
func EqualNormalized(left, right Result) bool {
	return left.NormalizedDigest == right.NormalizedDigest && reflect.DeepEqual(left.CanonicalJSON, right.CanonicalJSON)
}
