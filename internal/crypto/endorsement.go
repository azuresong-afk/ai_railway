package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"
)

// Заверение рабочего ключа производителя и подпись служебной базы
// (ADR-0022, п. 2; ADR-0027, п. 2–3). Ключ производителя подписывает
// заявление о рабочем ключе: назначение, открытый ключ, срок и номер. Рабочим
// ключом подписываются служебные базы (каталог теневого ИИ) и лицензии
// (ADR-0026). У каждой подписи свой контекст: подпись манифеста нельзя
// выдать за заверение, заверение — за базу, и наоборот.
//
// Подписываются байты заявления и содержимого как есть, поэтому канонизация
// JSON не нужна. Разбор строгий и покрыт fuzz-тестами (FuzzParseEndorsement,
// FuzzParseServiceDB): файл приходит из недоверенного места (загрузка через
// API), а заявление разбирается только после проверки подписи.

// Контексты подписи.
const (
	endorsementContext = "aisec-vendor-subkey-v1"
	serviceDBContext   = "aisec-service-db-v1"
)

// Назначения рабочих ключей.
const (
	// PurposeServiceDB — служебные базы (каталог доменов теневого ИИ).
	PurposeServiceDB = "service_db"
	// PurposeLicense — лицензии (ADR-0026).
	PurposeLicense = "license"
)

// Пределы форматов.
const (
	// MaxEndorsementSize — файл заверения.
	MaxEndorsementSize = 4 << 10
	// MaxServiceDBSize — файл служебной базы целиком; содержимое — до
	// MaxServiceDBPayload.
	MaxServiceDBSize    = 4 << 20
	MaxServiceDBPayload = 2 << 20
	// MaxEndorsementValidity — наибольший срок заверения.
	MaxEndorsementValidity = 5 * 366 * 24 * time.Hour
	maxEndorsementComment  = 200
	maxEndorsementSerial   = 1<<53 - 1
	maxServiceDBKind       = 64
)

// Виды PEM рабочего ключа: закрытый хранится как ключ производителя
// (ADR-0022, п. 3), открытый переносится на машину подписи для заверения.
const (
	KeyKindVendorSubkey       = "AISEC VENDOR SUBKEY"
	KeyKindVendorSubkeyPublic = "AISEC VENDOR SUBKEY PUBLIC KEY"
)

// Ошибки проверки. Текст не содержит байтов файла.
var (
	ErrEndorsementFormat    = errors.New("заверение рабочего ключа: неверный формат")
	ErrEndorsementSignature = errors.New("заверение рабочего ключа: подпись не ключом производителя")
	ErrEndorsementPurpose   = errors.New("заверение рабочего ключа: другое назначение")
	ErrEndorsementExpired   = errors.New("заверение рабочего ключа: вне срока действия")
	ErrEndorsementRevoked   = errors.New("заверение рабочего ключа: отозвано")
	ErrServiceDBFormat      = errors.New("служебная база: неверный формат")
	ErrServiceDBSignature   = errors.New("служебная база: подпись неверна")
	ErrServiceDBKind        = errors.New("служебная база: другой вид базы")
)

// Endorsement — заявление о рабочем ключе.
type Endorsement struct {
	Purpose   string
	Profile   string
	Serial    uint64
	PublicKey []byte
	NotBefore time.Time
	NotAfter  time.Time
	Comment   string
}

// ValidAt — момент t внутри срока заверения (границы включены).
func (e Endorsement) ValidAt(t time.Time) bool {
	return !t.Before(e.NotBefore) && !t.After(e.NotAfter)
}

type endorsementJSON struct {
	Format    string `json:"format"`
	Purpose   string `json:"purpose"`
	Profile   string `json:"profile"`
	Serial    uint64 `json:"serial"`
	PublicKey string `json:"public_key"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Comment   string `json:"comment,omitempty"`
}

func validPurpose(p string) bool { return p == PurposeServiceDB || p == PurposeLicense }

// check проверяет поля заявления до кодирования и после разбора.
func (e Endorsement) check() error {
	switch {
	case !validPurpose(e.Purpose):
		return fmt.Errorf("назначение — %s или %s", PurposeServiceDB, PurposeLicense)
	case e.Profile != ProfileStandard && e.Profile != ProfileGOST:
		return errors.New("неизвестный криптопрофиль")
	case e.Serial == 0 || e.Serial > maxEndorsementSerial:
		return fmt.Errorf("номер — от 1 до %d", uint64(maxEndorsementSerial))
	case len(e.PublicKey) != PublicKeySize:
		return fmt.Errorf("открытый ключ — %d байт", PublicKeySize)
	case e.NotBefore.IsZero() || e.NotAfter.IsZero() || !e.NotAfter.After(e.NotBefore):
		return errors.New("срок: not_after позже not_before")
	case e.NotAfter.Sub(e.NotBefore) > MaxEndorsementValidity:
		return errors.New("срок заверения больше 5 лет")
	case utf8.RuneCountInString(e.Comment) > maxEndorsementComment || !utf8.ValidString(e.Comment) || hasControlRune(e.Comment):
		return fmt.Errorf("комментарий — до %d символов без управляющих", maxEndorsementComment)
	}
	return nil
}

const endorsementTime = time.RFC3339

// EncodeEndorsementStatement — байты заявления для подписи.
func EncodeEndorsementStatement(e Endorsement) ([]byte, error) {
	e.NotBefore = e.NotBefore.UTC().Truncate(time.Second)
	e.NotAfter = e.NotAfter.UTC().Truncate(time.Second)
	if err := e.check(); err != nil {
		return nil, fmt.Errorf("заявление о рабочем ключе: %w", err)
	}
	return json.Marshal(endorsementJSON{Format: endorsementContext, Purpose: e.Purpose, Profile: e.Profile, Serial: e.Serial,
		PublicKey: base64.StdEncoding.EncodeToString(e.PublicKey), NotBefore: e.NotBefore.Format(endorsementTime),
		NotAfter: e.NotAfter.Format(endorsementTime), Comment: e.Comment})
}

func endorsementMessage(statement []byte) []byte {
	return append([]byte(endorsementContext+"\n"), statement...)
}

type signedJSON struct {
	Statement string `json:"statement"`
	Signature string `json:"signature"`
}

// SignEndorsement подписывает заявление ключом производителя и возвращает
// файл заверения (команда endorse инструмента подписи, на машине без сети).
func SignEndorsement(vendor Signer, e Endorsement) ([]byte, error) {
	if vendor == nil {
		return nil, errors.New("заверение: нет ключа производителя")
	}
	st, err := EncodeEndorsementStatement(e)
	if err != nil {
		return nil, err
	}
	sig, err := vendor.Sign(endorsementMessage(st))
	if err != nil {
		return nil, fmt.Errorf("заверение: %w", err)
	}
	out, err := json.Marshal(signedJSON{Statement: base64.StdEncoding.EncodeToString(st), Signature: base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// strictFields разбирает объект JSON без повторяющихся ключей (jsonObject)
// и проверяет, что ключи — ровно из allowed, а обязательные есть: сравнение
// точное, без учёта регистра encoding/json для структур.
func strictFields(data []byte, required, optional []string) (map[string]json.RawMessage, error) {
	m, err := jsonObject(data)
	if err != nil {
		return nil, err
	}
	for k := range m {
		if !slices.Contains(required, k) && !slices.Contains(optional, k) {
			return nil, errors.New("неизвестное поле")
		}
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return nil, errors.New("нет обязательного поля")
		}
	}
	return m, nil
}

func rawStringField(m map[string]json.RawMessage, name string) (string, error) {
	raw, ok := m[name]
	if !ok {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", errors.New("поле не строка")
	}
	return s, nil
}

func strictBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, errors.New("неверный base64")
	}
	return b, nil
}

// signedEnvelope — заявление и подпись из файла заверения, без проверки.
func signedEnvelope(data []byte) (statement, sig []byte, err error) {
	if len(data) > MaxEndorsementSize {
		return nil, nil, ErrEndorsementFormat
	}
	m, err := strictFields(data, []string{"statement", "signature"}, nil)
	if err != nil {
		return nil, nil, ErrEndorsementFormat
	}
	st, err := rawStringField(m, "statement")
	if err != nil {
		return nil, nil, ErrEndorsementFormat
	}
	sg, err := rawStringField(m, "signature")
	if err != nil {
		return nil, nil, ErrEndorsementFormat
	}
	if statement, err = strictBase64(st); err != nil {
		return nil, nil, ErrEndorsementFormat
	}
	if sig, err = strictBase64(sg); err != nil {
		return nil, nil, ErrEndorsementFormat
	}
	return statement, sig, nil
}

// ParseEndorsementStatement строго разбирает заявление. Вызывается только
// после проверки подписи (VerifyEndorsement) или для показа файла
// (InspectEndorsement), поэтому сам по себе доверия не даёт.
func ParseEndorsementStatement(data []byte) (Endorsement, error) {
	m, err := strictFields(data, []string{"format", "purpose", "profile", "serial", "public_key", "not_before", "not_after"},
		[]string{"comment"})
	if err != nil {
		return Endorsement{}, ErrEndorsementFormat
	}
	var j endorsementJSON
	for name, dst := range map[string]*string{"format": &j.Format, "purpose": &j.Purpose, "profile": &j.Profile,
		"public_key": &j.PublicKey, "not_before": &j.NotBefore, "not_after": &j.NotAfter, "comment": &j.Comment} {
		if *dst, err = rawStringField(m, name); err != nil {
			return Endorsement{}, ErrEndorsementFormat
		}
	}
	// Номер — целое без дробной части и экспоненты: json.Number из
	// jsonObject не годится для uint64 напрямую.
	if err := json.Unmarshal(m["serial"], &j.Serial); err != nil || !bytes.Equal(bytes.TrimSpace(m["serial"]), []byte(fmt.Sprint(j.Serial))) {
		return Endorsement{}, ErrEndorsementFormat
	}
	if j.Format != endorsementContext {
		return Endorsement{}, ErrEndorsementFormat
	}
	e := Endorsement{Purpose: j.Purpose, Profile: j.Profile, Serial: j.Serial, Comment: j.Comment}
	if e.PublicKey, err = strictBase64(j.PublicKey); err != nil {
		return Endorsement{}, ErrEndorsementFormat
	}
	if e.NotBefore, err = parseEndorsementTime(j.NotBefore); err != nil {
		return Endorsement{}, ErrEndorsementFormat
	}
	if e.NotAfter, err = parseEndorsementTime(j.NotAfter); err != nil {
		return Endorsement{}, ErrEndorsementFormat
	}
	if err := e.check(); err != nil {
		return Endorsement{}, ErrEndorsementFormat
	}
	return e, nil
}

// parseEndorsementTime — только UTC с суффиксом Z и точностью до секунды:
// одно время — одна запись.
func parseEndorsementTime(s string) (time.Time, error) {
	t, err := time.Parse(endorsementTime, s)
	if err != nil || t.Location() != time.UTC || t.Format(endorsementTime) != s {
		return time.Time{}, errors.New("время не в формате ГГГГ-ММ-ДДTЧЧ:ММ:ССZ")
	}
	return t, nil
}

// EndorsementCheck — условия проверки заверения.
type EndorsementCheck struct {
	// Purpose — ожидаемое назначение.
	Purpose string
	// At — момент, на который проверяется срок; нулевой — срок не
	// проверяется (уже загруженная база, ADR-0027, п. 3).
	At time.Time
	// Revoked — номер отозван (список встроен в выпуск); nil — отозванных нет.
	Revoked func(serial uint64) bool
}

// VerifyEndorsement проверяет файл заверения ключом производителя vendor
// (integrity.EmbeddedVerifier) и возвращает заявление и ключ проверки
// подписей рабочего ключа.
func VerifyEndorsement(p Provider, vendor Verifier, data []byte, c EndorsementCheck) (Endorsement, Verifier, error) {
	if p == nil || vendor == nil {
		return Endorsement{}, nil, errors.New("заверение: нет криптопрофиля или ключа производителя")
	}
	st, sig, err := signedEnvelope(data)
	if err != nil {
		return Endorsement{}, nil, err
	}
	if !vendor.Verify(endorsementMessage(st), sig) {
		return Endorsement{}, nil, ErrEndorsementSignature
	}
	e, err := ParseEndorsementStatement(st)
	if err != nil {
		return Endorsement{}, nil, err
	}
	switch {
	case e.Purpose != c.Purpose:
		return Endorsement{}, nil, ErrEndorsementPurpose
	case e.Profile != p.Name():
		return Endorsement{}, nil, fmt.Errorf("%w: ключ профиля %s, установка — %s", ErrEndorsementFormat, e.Profile, p.Name())
	case c.Revoked != nil && c.Revoked(e.Serial):
		return Endorsement{}, nil, ErrEndorsementRevoked
	case !c.At.IsZero() && !e.ValidAt(c.At):
		return Endorsement{}, nil, ErrEndorsementExpired
	}
	v, err := p.NewVerifier(e.PublicKey)
	if err != nil {
		return Endorsement{}, nil, err
	}
	return e, v, nil
}

// InspectEndorsement разбирает файл заверения без проверки подписи — для
// показа (inspect-db). Доверять результату нельзя.
func InspectEndorsement(data []byte) (Endorsement, error) {
	st, _, err := signedEnvelope(data)
	if err != nil {
		return Endorsement{}, err
	}
	return ParseEndorsementStatement(st)
}

// ServiceDB — проверенная служебная база.
type ServiceDB struct {
	Kind        string
	Payload     []byte
	Endorsement Endorsement
}

func serviceDBMessage(kind string, payload []byte) []byte {
	msg := make([]byte, 0, len(serviceDBContext)+len(kind)+2+len(payload))
	msg = append(msg, serviceDBContext+"\n"...)
	msg = append(msg, kind...)
	msg = append(msg, '\n')
	return append(msg, payload...)
}

// validDBKind — вид базы: латиница в нижнем регистре, цифры и «_».
func validDBKind(k string) bool {
	if k == "" || len(k) > maxServiceDBKind {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

type serviceDBJSON struct {
	Format      string          `json:"format"`
	Kind        string          `json:"kind"`
	Endorsement json.RawMessage `json:"endorsement"`
	Payload     string          `json:"payload"`
	Signature   string          `json:"signature"`
}

// SignServiceDB подписывает содержимое базы вида kind рабочим ключом sub и
// возвращает файл базы с заверением внутри (команда sign-db). Ключ должен
// совпадать с ключом из заверения.
func SignServiceDB(sub Signer, endorsement []byte, kind string, payload []byte) ([]byte, error) {
	if sub == nil {
		return nil, errors.New("служебная база: нет рабочего ключа")
	}
	if !validDBKind(kind) || len(payload) == 0 || len(payload) > MaxServiceDBPayload {
		return nil, fmt.Errorf("служебная база: неверный вид или размер содержимого (до %d байт)", MaxServiceDBPayload)
	}
	e, err := InspectEndorsement(endorsement)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(e.PublicKey, sub.PublicKey()) {
		return nil, errors.New("служебная база: рабочий ключ не совпадает с ключом из заверения")
	}
	if e.Purpose != PurposeServiceDB {
		return nil, ErrEndorsementPurpose
	}
	sig, err := sub.Sign(serviceDBMessage(kind, payload))
	if err != nil {
		return nil, fmt.Errorf("служебная база: %w", err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, endorsement); err != nil {
		return nil, ErrEndorsementFormat
	}
	out, err := json.Marshal(serviceDBJSON{Format: serviceDBContext, Kind: kind, Endorsement: compact.Bytes(),
		Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		return nil, err
	}
	if len(out) >= MaxServiceDBSize {
		return nil, fmt.Errorf("служебная база: файл больше %d байт", MaxServiceDBSize)
	}
	return append(out, '\n'), nil
}

// parseServiceDB — части файла базы без проверки подписей.
func parseServiceDB(data []byte) (kind string, endorsement, payload, sig []byte, err error) {
	if len(data) > MaxServiceDBSize {
		return "", nil, nil, nil, ErrServiceDBFormat
	}
	m, err := strictFields(data, []string{"format", "kind", "endorsement", "payload", "signature"}, nil)
	if err != nil {
		return "", nil, nil, nil, ErrServiceDBFormat
	}
	var j serviceDBJSON
	for name, dst := range map[string]*string{"format": &j.Format, "kind": &j.Kind, "payload": &j.Payload, "signature": &j.Signature} {
		if *dst, err = rawStringField(m, name); err != nil {
			return "", nil, nil, nil, ErrServiceDBFormat
		}
	}
	if j.Format != serviceDBContext || !validDBKind(j.Kind) {
		return "", nil, nil, nil, ErrServiceDBFormat
	}
	endorsement = m["endorsement"]
	if len(endorsement) == 0 || endorsement[0] != '{' {
		return "", nil, nil, nil, ErrServiceDBFormat
	}
	if payload, err = strictBase64(j.Payload); err != nil || len(payload) > MaxServiceDBPayload {
		return "", nil, nil, nil, ErrServiceDBFormat
	}
	if sig, err = strictBase64(j.Signature); err != nil {
		return "", nil, nil, nil, ErrServiceDBFormat
	}
	return j.Kind, endorsement, payload, sig, nil
}

// VerifyServiceDB проверяет файл служебной базы вида kind: заверение
// рабочего ключа ключом производителя vendor (назначение service_db, срок —
// на c.At, отзыв), затем подпись содержимого рабочим ключом. Содержимое
// разбирает модуль базы и сверяет его дату со сроком заверения.
func VerifyServiceDB(p Provider, vendor Verifier, data []byte, kind string, c EndorsementCheck) (ServiceDB, error) {
	c.Purpose = PurposeServiceDB
	k, endorsement, payload, sig, err := parseServiceDB(data)
	if err != nil {
		return ServiceDB{}, err
	}
	e, v, err := VerifyEndorsement(p, vendor, endorsement, c)
	if err != nil {
		return ServiceDB{}, err
	}
	if !v.Verify(serviceDBMessage(k, payload), sig) {
		return ServiceDB{}, ErrServiceDBSignature
	}
	if k != kind {
		return ServiceDB{}, ErrServiceDBKind
	}
	return ServiceDB{Kind: k, Payload: payload, Endorsement: e}, nil
}

// InspectServiceDB — вид, содержимое и заявление без проверки подписей (для
// показа в inspect-db). Доверять результату нельзя.
func InspectServiceDB(data []byte) (ServiceDB, error) {
	k, endorsement, payload, _, err := parseServiceDB(data)
	if err != nil {
		return ServiceDB{}, err
	}
	e, err := InspectEndorsement(endorsement)
	if err != nil {
		return ServiceDB{}, err
	}
	return ServiceDB{Kind: k, Payload: payload, Endorsement: e}, nil
}
