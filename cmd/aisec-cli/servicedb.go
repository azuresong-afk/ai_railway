package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
	"github.com/azuresong-afk/ai_railway/internal/servicedb/kinds"
)

// errServiceDBRejected — файл не будет принят этим выпуском (код выхода 1).
var errServiceDBRejected = errors.New("файл не прошёл проверку")

// servicedbCmd — служебные базы (ОБН.4, ADR-0028, п. 8). Подписи ключом
// производителя в поставляемом aisec-cli нет: базу подписывает производитель
// на машине без сети (aisec-manifest-sign sign-db). Здесь — только проверка
// файла заказчиком в закрытом контуре до загрузки, без сети и без БД.
func servicedbCmd(args []string, stdout, stderr io.Writer, now time.Time) error {
	if len(args) > 0 && args[0] == "inspect" {
		return servicedbInspect(args[1:], stdout, stderr, now)
	}
	return errors.New("подкоманда: inspect ФАЙЛ")
}

func servicedbInspect(args []string, stdout, stderr io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("servicedb inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("укажите один файл служебной базы (.aisecdb)")
	}
	data, err := readServiceDBFile(fs.Arg(0))
	if err != nil {
		return err
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	vendor, err := servicedb.EmbeddedVendor(p)
	if err != nil {
		return err
	}
	r, err := servicedb.Inspect(p, vendor, kinds.All(), data, now.UTC())
	if err != nil {
		return fmt.Errorf("%s: не служебная база: %w", fs.Arg(0), err)
	}
	title := r.Title
	if title == "" {
		title = "неизвестен этому выпуску"
	}
	e := r.Endorsement
	say(stdout, "Вид: %s (%s)\n", r.Kind, title)
	if r.Verified {
		say(stdout, "Версия: %d от %s, записей: %d\n", r.Version, r.Date.Format(time.DateOnly), r.Records)
	}
	say(stdout, "Заверение рабочего ключа: номер %d, срок %s — %s\nОтпечаток рабочего ключа: %s\n",
		e.Serial, e.NotBefore.UTC().Format(time.RFC3339), e.NotAfter.UTC().Format(time.RFC3339), r.Fingerprint)
	if !r.Verified {
		say(stdout, "Итог: НЕ ПРИНЯТ — %s\n", inspectReasonText(r.Reason))
		return errServiceDBRejected
	}
	say(stdout, "Итог: подпись, заверение, отзыв, срок и содержимое проверены встроенным ключом производителя.\n"+
		"Сервер примет файл, если его версия больше загруженной.\n")
	return nil
}

// readServiceDBFile читает обычный файл не больше предела служебной базы:
// предел проверяется до чтения.
func readServiceDBFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > aisecCrypto.MaxServiceDBSize {
		return nil, fmt.Errorf("%s: не обычный файл или больше %d байт", path, aisecCrypto.MaxServiceDBSize)
	}
	f, err := os.Open(path) //nolint:gosec // G304: путь задаёт администратор в командной строке
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() //nolint:gosec // G104: файл только читается
	data, err := io.ReadAll(io.LimitReader(f, aisecCrypto.MaxServiceDBSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > aisecCrypto.MaxServiceDBSize {
		return nil, fmt.Errorf("%s: больше %d байт", path, aisecCrypto.MaxServiceDBSize)
	}
	return data, nil
}

// inspectReasonText — причина отказа словами (ТЗ 6.7).
func inspectReasonText(reason string) string {
	switch reason {
	case servicedb.ReasonSignature:
		return "подпись файла или заверения неверна: файл изменён или выпущен не производителем"
	case servicedb.ReasonPurpose:
		return "ключ заверен не для служебных баз"
	case servicedb.ReasonKind:
		return "вид базы неизвестен этому выпуску"
	case servicedb.ReasonExpired:
		return "срок заверения ключа истёк или ещё не наступил"
	case servicedb.ReasonRevoked:
		return "ключ отозван производителем"
	case servicedb.ReasonDate:
		return "дата выпуска базы вне срока заверения ключа"
	case servicedb.ReasonContent:
		return "содержимое базы не прошло проверку этого выпуска"
	}
	return "неверный формат файла"
}
