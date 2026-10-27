package agents

import (
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy/tooldesc"
)

// Описание инструмента и его хеш — internal/policy/tooldesc: одна функция
// для сервера, шлюза и самотеста (ADR-0023, раздел 1).

// DescriptorDomain — префикс домена хеша описания.
const DescriptorDomain = tooldesc.Domain

// MaxDescriptorSize — предел описания инструмента.
const MaxDescriptorSize = tooldesc.MaxSize

// ErrDescriptor — описание инструмента не разбирается или не подходит.
var ErrDescriptor = tooldesc.ErrDescriptor

// Descriptor — разобранное описание инструмента.
type Descriptor = tooldesc.Descriptor

// ParseDescriptor разбирает описание инструмента из tools/list.
func ParseDescriptor(raw []byte) (Descriptor, error) { return tooldesc.Parse(raw) }

// DescriptorHash — хеш описания на криптопрофиле.
func DescriptorHash(h aisecCrypto.Hasher, d Descriptor) []byte { return tooldesc.Hash(h, d) }
