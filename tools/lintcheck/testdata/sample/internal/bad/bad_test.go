package bad

import (
	"math/rand/v2" // want:depguard
	"reflect"      // clean:depguard
	"testing"
)

func TestUse(t *testing.T) {
	_ = rand.Int()
	_ = reflect.TypeOf(t)
}
