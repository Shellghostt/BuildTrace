package signing

import (
	"bytes"
	"encoding/json"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// canonicalProtoJSON rejects protobuf's alternate snake_case field aliases and
// noncanonical byte encodings in security input. Protobuf remains responsible
// for scalar types/enums/time syntax; this is a strict JSON-name/byte guard.
func canonicalProtoJSON(raw []byte, descriptor protoreflect.MessageDescriptor) error {
	if descriptor.FullName() == "google.protobuf.Timestamp" {
		_, err := securityString(raw, 64, true)
		return err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return invalid("invalid security protobuf object")
	}
	for name, value := range object {
		field := descriptor.Fields().ByJSONName(name)
		if field == nil || name != field.JSONName() || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return invalid("unknown, aliased or null security protobuf field")
		}
		values := []json.RawMessage{value}
		if field.IsList() {
			if json.Unmarshal(value, &values) != nil || values == nil {
				return invalid("invalid security protobuf array")
			}
		}
		for _, item := range values {
			if field.Kind() == protoreflect.MessageKind {
				if err := canonicalProtoJSON(item, field.Message()); err != nil {
					return err
				}
			} else if field.Kind() == protoreflect.BytesKind {
				encoded, err := securityString(item, (MaxTrustBytes+2)/3*4, true)
				if err != nil {
					return err
				}
				if _, err := strictBase64(encoded, MaxTrustBytes); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
