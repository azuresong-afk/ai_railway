package bundle_test

import (
	"bytes"
	"testing"
)

// Признак on_premise провайдера пакета (задача 5.28 этапа 5, ADR-0030,
// раздел 1): без него байты пакета прежние; с ним провайдер — невнешний
// типа openai.
func TestProviderOnPremise(t *testing.T) {
	c := budgetsContent(t, nil)
	before, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("on_premise")) {
		t.Fatal("ложный признак выводится в пакет")
	}
	c.Providers[0].OnPremise = true
	c.Providers[0].External = true
	if err := c.Validate(); err == nil {
		t.Fatal("внешний провайдер «у заказчика» принят")
	}
	c.Providers[0].External = false
	if err := c.Validate(); err != nil {
		t.Fatalf("невнешний провайдер openai: %v", err)
	}
	c.Providers[0].Type, c.Providers[0].Scope = "gigachat", "GIGACHAT_API_CORP"
	if err := c.Validate(); err == nil {
		t.Fatal("GigaChat «у заказчика» принят")
	}
}
