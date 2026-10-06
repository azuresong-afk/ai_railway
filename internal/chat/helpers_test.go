package chat

import "encoding/json"

func marshalJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
