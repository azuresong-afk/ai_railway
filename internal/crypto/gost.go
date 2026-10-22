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

func (gost) PasswordHasher() (PasswordHasher, error) { return nil, ErrNotImplemented }
func (gost) PassphraseKDF() (PassphraseKDF, error)   { return nil, ErrNotImplemented }
func (gost) NewAEAD([]byte) (AEAD, error)            { return nil, ErrNotImplemented }
func (gost) GenerateSigner() (Signer, error)         { return nil, ErrNotImplemented }
func (gost) NewSigner([]byte) (Signer, error)        { return nil, ErrNotImplemented }
func (gost) NewVerifier([]byte) (Verifier, error)    { return nil, ErrNotImplemented }

// NewTOTP: применимость исключения HMAC-SHA-1 в профиле gost решается вместе
// с выбором СКЗИ на этапе 6 (ADR-0006).
func (gost) NewTOTP([]byte) (TOTP, error) { return nil, ErrNotImplemented }

// NewKDF: в профиле gost — KDF на «Стрибоге» (Р 50.1.113-2016) через СКЗИ этапа 6.
func (gost) NewKDF([]byte) (KDF, error) { return nil, ErrNotImplemented }

// Шифрование по открытому ключу в профиле gost — через СКЗИ этапа 6.
func (gost) GenerateRecipient() (Recipient, error)  { return nil, ErrNotImplemented }
func (gost) NewRecipient([]byte) (Recipient, error) { return nil, ErrNotImplemented }
func (gost) SealTo(_, _, _ []byte) ([]byte, error)  { return nil, ErrNotImplemented }
