// XOR field de-obfuscation: encoded_value = plain_value ^ CONSTANT.
//
// The constants live as `// xor: N` comments above the field in the .proto
// sources. They are parsed into a (message, field) -> constant table and applied
// after decode. Only integer fields are touched -- XOR'ing a bool or string gives
// garbage, and a wrong guess is worse than no decode.
//
// Enabled with -xor, off by default: the constants come from the upstream
// descriptor table but the client does not enforce them uniformly. 24 protos
// annotate `retcode`, yet its tag never appears on the wire at all, so in proto3
// the value was a plain 0 and -xor would report a nonzero retcode for a
// successful response. Treat an annotation as unverified until you have seen its
// field on the wire.
//
// Constants recovered by auto-detection are applied regardless of -xor: those
// were established against real traffic, which is a different kind of knowledge.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	descriptorpb "github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/dynamic"
)

// xorEnabled is set from the -xor command line flag.
var xorEnabled bool

// xorTable maps message name -> field name -> constant.
var xorTable = map[string]map[string]uint64{}

var (
	xorCommentRe = regexp.MustCompile(`//\s*xor:\s*(\d+)`)
	messageRe    = regexp.MustCompile(`^\s*message\s+(\w+)`)
	fieldRe      = regexp.MustCompile(`^\s*(?:repeated\s+|optional\s+|required\s+)?([A-Za-z_][\w.]*)\s+([A-Za-z_]\w*)\s*=\s*(\d+)\s*;`)
	intTypeRe    = regexp.MustCompile(`^(u?int|s?fixed)(32|64)$`)
)

// loadXorTable scans a directory of .proto files for `// xor: N` annotations.
// The comment sits above its field, so one pending constant is carried forward
// and bound to the next declaration; a brace stack keeps nested messages apart.
func loadXorTable(protoDir string) (int, error) {
	entries, err := os.ReadDir(protoDir)
	if err != nil {
		return 0, fmt.Errorf("read proto dir %s: %w", protoDir, err)
	}

	// Reset so the result is a full recount rather than "how many were new".
	xorTable = map[string]map[string]uint64{}

	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".proto") {
			continue
		}
		path := filepath.Join(protoDir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var scope []string // enclosing message names
		var kinds []string // 'message' / 'other' for each open brace
		var pending uint64 // constant seen on the previous line
		havePending := false

		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)

			if m := xorCommentRe.FindStringSubmatch(line); m != nil {
				n, err := strconv.ParseUint(m[1], 10, 64)
				if err == nil {
					pending, havePending = n, true
				}
				continue
			}
			if trimmed == "" {
				continue
			}

			// Scope first: `message Foo {` is not itself a field.
			if m := messageRe.FindStringSubmatch(line); m != nil {
				scope = append(scope, m[1])
				kinds = append(kinds, "message")
				havePending = false
				continue
			}
			if strings.HasPrefix(trimmed, "}") {
				if len(scope) > 0 {
					scope = scope[:len(scope)-1]
				}
				if len(kinds) > 0 {
					kinds = kinds[:len(kinds)-1]
				}
				havePending = false
				continue
			}
			if strings.Contains(trimmed, "{") {
				kinds = append(kinds, "other")
				havePending = false
				continue
			}
			if strings.HasPrefix(trimmed, "enum ") || strings.HasPrefix(trimmed, "import ") ||
				strings.HasPrefix(trimmed, "syntax") || strings.HasPrefix(trimmed, "package") {
				havePending = false
				continue
			}
			if strings.HasPrefix(trimmed, "oneof") {
				havePending = false
				continue
			}

			m := fieldRe.FindStringSubmatch(line)
			if m == nil {
				// Drop the pending constant so it cannot leak onto a later field.
				if trimmed != "" {
					havePending = false
				}
				continue
			}

			typ, name := m[1], m[2]
			if havePending && len(scope) > 0 {
				// Integers only; see the package comment.
				if intTypeRe.MatchString(typ) {
					msg := scope[len(scope)-1]
					if xorTable[msg] == nil {
						xorTable[msg] = map[string]uint64{}
					}
					if _, dup := xorTable[msg][name]; !dup {
						xorTable[msg][name] = pending
						found++
					}
				}
			}
			havePending = false
		}
	}
	return found, nil
}

func xorConstantFor(fd *desc.FieldDescriptor) (uint64, bool) {
	if fd == nil {
		return 0, false
	}
	msg := fd.GetOwner()
	if msg == nil {
		return 0, false
	}
	fqn := msg.GetFullyQualifiedName()
	// A recovered constant wins over an annotation.
	if fields, ok := detectedXor[fqn]; ok {
		if k, ok := fields[fd.GetName()]; ok {
			return k, true
		}
	}
	fields, ok := xorTable[fqn]
	if !ok {
		return 0, false
	}
	k, ok := fields[fd.GetName()]
	return k, ok
}

// xorInt applies the constant to an integer of any width. Non-integers pass
// through untouched.
func xorInt(v interface{}, k uint64) (interface{}, bool) {
	switch n := v.(type) {
	case int32:
		return int32(uint32(n) ^ uint32(k)), true
	case uint32:
		return n ^ uint32(k), true
	case int64:
		return int64(uint64(n) ^ k), true
	case uint64:
		return n ^ k, true
	case int:
		return int(uint32(n) ^ uint32(k)), true
	case uint:
		return uint(uint32(n) ^ uint32(k)), true
	default:
		return v, false
	}
}

func isMessageValued(fd *desc.FieldDescriptor) bool {
	if fd == nil {
		return false
	}
	return fd.GetType() == descriptorpb.FieldDescriptorProto_TYPE_MESSAGE ||
		fd.GetType() == descriptorpb.FieldDescriptorProto_TYPE_GROUP
}

// detectedXor holds constants recovered by detection rather than read from a
// proto annotation. Applied unconditionally; see the package comment.
var detectedXor = map[string]map[string]uint64{}

func forceXor(msgName, field string, k uint64) {
	if detectedXor[msgName] == nil {
		detectedXor[msgName] = map[string]uint64{}
	}
	detectedXor[msgName][field] = k
}

// applyXors walks a decoded message and XOR's every annotated integer field,
// converting encoded -> plain. Call it once per message.
func applyXors(msgName string, m *dynamic.Message) int {
	if m == nil || (!xorEnabled && len(detectedXor) == 0) {
		return 0
	}
	return applyXorsInner(msgName, m)
}

func applyXorsInner(msgName string, m *dynamic.Message) int {
	if m == nil {
		return 0
	}
	md := m.GetMessageDescriptor()
	if md == nil {
		return 0
	}
	// Prefer the fully-qualified name so same-named messages in different
	// packages stay distinct.
	if fqn := md.GetFullyQualifiedName(); fqn != "" {
		msgName = fqn
	}

	applied := 0
	for _, fd := range md.GetFields() {
		// Skip absent fields, or every proto3 default gets materialised and XOR'd.
		if !m.HasField(fd) {
			continue
		}

		val := m.GetField(fd)
		if val == nil {
			continue
		}

		if sub, ok := val.(*dynamic.Message); ok {
			applied += applyXorsInner(fd.GetMessageType().GetFullyQualifiedName(), sub)
			continue
		}

		// Repeated message field.
		if fd.IsRepeated() && !fd.IsMap() {
			if items, ok := val.([]interface{}); ok {
				for _, it := range items {
					if sub, ok := it.(*dynamic.Message); ok {
						applied += applyXorsInner(fd.GetMessageType().GetFullyQualifiedName(), sub)
					}
				}
				continue
			}
		}

		// Map values may be annotated too.
		if fd.IsMap() {
			if mm, ok := val.(map[interface{}]interface{}); ok {
				valDesc := fd.GetMessageType().FindFieldByName("value")
				if k, ok := xorConstantFor(valDesc); ok && !isMessageValued(valDesc) {
					out := make(map[interface{}]interface{}, len(mm))
					for mk, mv := range mm {
						nv, changed := xorInt(mv, k)
						if changed {
							applied++
						}
						out[mk] = nv
					}
					m.SetField(fd, out)
				}
				continue
			}
		}

		if fd.IsRepeated() {
			if items, ok := val.([]interface{}); ok {
				k, ok := xorConstantFor(fd)
				if !ok {
					continue
				}
				out := make([]interface{}, len(items))
				for i, it := range items {
					nv, changed := xorInt(it, k)
					if changed {
						applied++
					}
					out[i] = nv
				}
				m.SetField(fd, out)
			}
			continue
		}

		k, ok := xorConstantFor(fd)
		if !ok {
			continue
		}
		if nv, changed := xorInt(val, k); changed {
			m.SetField(fd, nv)
			applied++
		}
	}
	return applied
}
