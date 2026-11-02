package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// StoredChannel — канал в том виде, в каком его хранит сервер: settings —
// JSON из БД, Secrets — расшифрованный JSON секретов (nil — секретов нет).
// Источник — копия конфигурации (задача 5.8 этапа 5).
type StoredChannel struct {
	Name         string
	Type         string
	Enabled      bool
	MinSeverity  string
	Settings     json.RawMessage
	SecretFields []string
	Secrets      []byte
	AuditStream  bool
}

// CheckStoredChannel проверяет сохранённый канал теми же правилами, что и
// сохранение через API (normalize): settings и секреты разбираются строго;
// канал проходит все проверки ввода; settings — ровно те, что записал бы
// сервер (значения по умолчанию, url_origin — по адресу webhook из
// секретов, иначе консоль показала бы другой адрес); secret_fields — по
// заданным секретам. Ошибка — *InputError с именами полей, без значений
// секретов. Вызывает восстановление копии до записи в БД (остаток 5.8,
// остатки волны A этапа 5).
func CheckStoredChannel(tlsp aisecCrypto.TLSProvider, c StoredChannel) error {
	var st Settings
	if err := decodeStrict(c.Settings, &st); err != nil {
		return invalidf("settings — некорректный JSON или неизвестные поля")
	}
	var sec Secrets
	if c.Secrets != nil {
		if err := decodeStrict(c.Secrets, &sec); err != nil {
			return invalidf("secrets — некорректный JSON или неизвестные поля")
		}
	}
	in := ChannelInput{Name: c.Name, Type: c.Type, Enabled: &c.Enabled, MinSeverity: c.MinSeverity, Settings: st,
		AuditStream: &c.AuditStream}
	got, err := normalize(&in, sec, tlsp)
	if err != nil {
		return err
	}
	var errs []error
	if in.Name != c.Name {
		errs = append(errs, errors.New("name — с пробелами по краям: сервер хранит название без них"))
	}
	if in.MinSeverity != c.MinSeverity {
		errs = append(errs, errors.New("min_severity — пустое значение: сервер хранит info"))
	}
	want, err1 := json.Marshal(in.Settings)
	have, err2 := json.Marshal(st)
	if err1 != nil || err2 != nil || !bytes.Equal(want, have) {
		errs = append(errs, errors.New("settings — не в том виде, в каком их сохраняет сервер (значения по умолчанию, url_origin)"))
	}
	fields := slices.Clone(c.SecretFields)
	slices.Sort(fields)
	if !slices.Equal(fields, got.fields()) {
		errs = append(errs, errors.New("secret_fields — не совпадают с заданными секретами канала"))
	}
	if len(errs) > 0 {
		return &InputError{Errs: errs}
	}
	return nil
}

// decodeStrict — разбор без неизвестных полей и данных после значения.
func decodeStrict(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("данные после значения")
	}
	return nil
}
