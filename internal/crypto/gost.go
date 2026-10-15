package crypto

// gost — профиль для госсектора и КИИ. Реализуется через сертифицированное
// СКЗИ на этапе 6 (ТЗ, 10.2); до этого все операции возвращают
// ErrNotImplemented, а контрактные тесты фиксируют это поведение.
type gost struct{}

func (gost) Name() string               { return ProfileGOST }
func (gost) Hasher() (Hasher, error)    { return nil, ErrNotImplemented }
func (gost) NewMAC([]byte) (MAC, error) { return nil, ErrNotImplemented }
func (gost) Random() (Random, error)    { return nil, ErrNotImplemented }
func (gost) TLS() (TLSProvider, error)  { return nil, ErrNotImplemented }
