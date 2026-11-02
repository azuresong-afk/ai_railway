package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/cliclient"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/rag"
)

// Проверка документов RAG до индексации для индексатора без своего
// HTTP-клиента (ТЗ 5.12, 5.16 DM-07 «RAG — 5»; задача 5.25 этапа 5,
// ADR-0029, п. 5): тексты из файлов уходят в POST /guard/v1/check/batch
// шлюза с ключом приложения пакетами до 100 документов; решение по каждому
// печатается, полный ответ (с текстом после маскирования) — в файл -out.

// errRAGExcluded — хотя бы один документ получил «исключить» (код выхода 3).
var errRAGExcluded = errors.New("есть документы, которые не нужно индексировать")

// Пределы команды.
const (
	// ragBatchDocuments и ragBatchBody — документов и байт тела в одном
	// пакете (пределы шлюза: 100 документов, тело — не меньше 8 МиБ).
	ragBatchDocuments = 100
	ragBatchBody      = 8<<20 - 64<<10
	// ragMaxFiles — файлов за запуск.
	ragMaxFiles = 100_000
	// ragDefaultMaxText — предел текста одного файла по умолчанию: предел
	// тела запроса шлюза по умолчанию (max-body-bytes).
	ragDefaultMaxText = 1 << 20
	// ragMaxResponse — предел ответа шлюза на пакет: тексты после
	// маскирования и находки.
	ragMaxResponse = 32 << 20
	ragCheckPath   = "/guard/v1/check/batch"
)

type ragFlags struct {
	gateway, ca, keyFile, profile, out, user string
	timeout                                  time.Duration
	maxText                                  int64
}

// ragDoc — документ пакета.
type ragDoc struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// ragResult — решение шлюза по документу (поля ответа, которые нужны
// команде; остальные переносятся в -out как есть).
type ragResult struct {
	ID         string          `json:"id"`
	EventID    string          `json:"event_id"`
	Decision   string          `json:"decision"`
	Action     string          `json:"action"`
	Reason     string          `json:"reason,omitempty"`
	Incomplete bool            `json:"incomplete,omitempty"`
	Findings   json.RawMessage `json:"findings"`
	Text       *string         `json:"text,omitempty"`
}

type ragResponse struct {
	Stage     string      `json:"stage"`
	Unchecked bool        `json:"unchecked,omitempty"`
	Excluded  int         `json:"excluded"`
	Results   []ragResult `json:"results"`
}

// ragCmd — aisec-cli rag check.
func ragCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "check" {
		return ragCheck(args[1:], stdout, stderr)
	}
	return errors.New("подкоманда: check")
}

func ragCheck(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("rag check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f ragFlags
	fs.StringVar(&f.gateway, "gateway", "", "адрес шлюза: https://хост[:порт]")
	fs.StringVar(&f.ca, "ca", "", "корневой сертификат шлюза (PEM): доверие — только ему")
	fs.StringVar(&f.keyFile, "key-file", "", "файл с ключом приложения шлюза (права 0600 или 0400)")
	fs.StringVar(&f.profile, "crypto-profile", aisecCrypto.ProfileStandard, "криптопрофиль TLS: standard или gost")
	fs.StringVar(&f.out, "out", "", "файл для полного ответа в JSON (решения, находки, текст после маскирования); создаётся с правами 0600")
	fs.StringVar(&f.user, "user", "", "идентификатор индексатора в событиях (до 256 байт)")
	fs.DurationVar(&f.timeout, "timeout", cliclient.DefaultTimeout, "срок одного пакета")
	fs.Int64Var(&f.maxText, "max-text", ragDefaultMaxText, "предел текста одного файла, байт (не больше предела тела запроса шлюза)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case fs.NArg() == 0:
		return errors.New("укажите файлы с текстами документов")
	case fs.NArg() > ragMaxFiles:
		return fmt.Errorf("не больше %d файлов за запуск", ragMaxFiles)
	case f.gateway == "" || f.ca == "" || f.keyFile == "":
		return errors.New("обязательны -gateway, -ca и -key-file")
	case f.timeout <= 0 || f.timeout > 10*time.Minute:
		return errors.New("-timeout: от 1 с до 10 мин")
	case f.maxText <= 0 || f.maxText > ragBatchBody/2:
		return fmt.Errorf("-max-text: от 1 до %d байт", ragBatchBody/2)
	case len(f.user) > 256 || !utf8.ValidString(f.user):
		return errors.New("-user: строка UTF-8 до 256 байт")
	}
	// Тексты читаются целиком до первого запроса: ошибка в файле не
	// оставляет половину коллекции проверенной.
	docs, err := readRAGDocs(fs.Args(), f.maxText)
	if err != nil {
		return err
	}
	p, err := aisecCrypto.New(f.profile)
	if err != nil {
		return fmt.Errorf("-crypto-profile: %w", err)
	}
	c, err := cliclient.New(cliclient.Options{Server: f.gateway, CAFile: f.ca, TokenFile: f.keyFile, Provider: p,
		Timeout: f.timeout, MaxResponse: ragMaxResponse})
	if err != nil {
		return err
	}
	all := ragResponse{Stage: "pre_index", Results: make([]ragResult, 0, len(docs))}
	for _, batch := range ragBatches(docs) {
		resp, err := sendRAGBatch(c, f.user, batch)
		if err != nil {
			return fmt.Errorf("проверено документов: %d из %d: %w", len(all.Results), len(docs), err)
		}
		all.Unchecked = all.Unchecked || resp.Unchecked
		all.Excluded += resp.Excluded
		all.Results = append(all.Results, resp.Results...)
	}
	for _, r := range all.Results {
		line := r.Decision + "\t" + r.ID
		switch {
		case r.Reason != "":
			line += "\t" + r.Reason
		case r.Text != nil:
			line += "\tтекст изменён политикой — индексируйте текст из -out"
		}
		if r.Incomplete {
			line += "\tпроверка неполная"
		}
		say(stdout, "%s\n", line)
	}
	if all.Unchecked {
		say(stderr, "ВНИМАНИЕ: у политики приложения нет правил для входа — детекторы не запускались, allow не означает «проверено»\n")
	}
	if f.out != "" {
		if err := writeRAGOut(f.out, all); err != nil {
			return err
		}
	}
	say(stdout, "Проверено документов: %d, не индексировать: %d.\n", len(all.Results), all.Excluded)
	if all.Excluded > 0 {
		return errRAGExcluded
	}
	return nil
}

// readRAGDocs читает тексты: ID документа — путь, как он указан (через
// «/»), по правилам ID манифеста коллекции; файл — обычный, не больше
// maxText байт, непустой текст UTF-8.
func readRAGDocs(paths []string, maxText int64) ([]ragDoc, error) {
	seen := make(map[string]bool, len(paths))
	docs := make([]ragDoc, 0, len(paths))
	for _, p := range paths {
		id := filepath.ToSlash(filepath.Clean(p))
		if err := rag.CheckDocumentID(id); err != nil {
			return nil, fmt.Errorf("%s: ID документа — путь к файлу: %w", p, err)
		}
		if seen[id] {
			return nil, fmt.Errorf("%s: файл указан дважды", p)
		}
		seen[id] = true
		text, err := readRAGText(p, maxText)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		docs = append(docs, ragDoc{ID: id, Text: text})
	}
	return docs, nil
}

func readRAGText(path string, maxText int64) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("не обычный файл")
	}
	if st.Size() > maxText {
		return "", fmt.Errorf("больше %d байт (-max-text)", maxText)
	}
	fh, err := os.Open(path) //nolint:gosec // G304: файлы для проверки называет администратор
	if err != nil {
		return "", err
	}
	defer fh.Close() //nolint:errcheck // файл только читается
	data, err := io.ReadAll(io.LimitReader(fh, maxText+1))
	if err != nil {
		return "", err
	}
	switch {
	case int64(len(data)) > maxText:
		return "", fmt.Errorf("больше %d байт (-max-text)", maxText)
	case len(data) == 0:
		return "", errors.New("пустой файл")
	case !utf8.Valid(data):
		return "", errors.New("текст не в UTF-8: передайте извлечённый текст документа")
	}
	return string(data), nil
}

// ragBatches делит документы на пакеты: до ragBatchDocuments документов и
// ragBatchBody байт тела в JSON (экранирование учтено).
func ragBatches(docs []ragDoc) [][]ragDoc {
	var out [][]ragDoc
	var cur []ragDoc
	size := 0
	for _, d := range docs {
		n := ragDocSize(d)
		if len(cur) > 0 && (len(cur) == ragBatchDocuments || size+n > ragBatchBody) {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, d)
		size += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// ragDocSize — размер документа в теле пакета.
func ragDocSize(d ragDoc) int {
	b, err := json.Marshal(d)
	if err != nil {
		return ragBatchBody
	}
	return len(b) + 1
}

func sendRAGBatch(c *cliclient.Client, user string, docs []ragDoc) (ragResponse, error) {
	body, err := json.Marshal(struct {
		Source    string   `json:"source"`
		Stage     string   `json:"stage"`
		User      string   `json:"user,omitempty"`
		Documents []ragDoc `json:"documents"`
	}{Source: "rag", Stage: "pre_index", User: user, Documents: docs})
	if err != nil {
		return ragResponse{}, err
	}
	var resp ragResponse
	if err := c.Do(context.Background(), "POST", ragCheckPath, body, "application/json", &resp); err != nil {
		return ragResponse{}, err
	}
	// Ответ сверяется с запросом: решения — по каждому документу в том же
	// порядке, иначе индексатор применил бы решение к чужому документу.
	if len(resp.Results) != len(docs) {
		return ragResponse{}, fmt.Errorf("шлюз вернул решений: %d, документов в пакете: %d", len(resp.Results), len(docs))
	}
	for i, r := range resp.Results {
		if r.ID != docs[i].ID {
			return ragResponse{}, fmt.Errorf("решение %d — не по документу пакета", i)
		}
		if r.Decision != "allow" && r.Decision != "exclude" {
			return ragResponse{}, fmt.Errorf("решение %d: неизвестное значение", i)
		}
	}
	return resp, nil
}

// writeRAGOut записывает полный ответ: новый файл с правами 0600 (тексты
// после маскирования — данные заказчика), существующий не перезаписывается.
func writeRAGOut(path string, all ragResponse) error {
	data, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: путь задаёт администратор
	if err != nil {
		return fmt.Errorf("-out: %w", err)
	}
	if _, err := fh.Write(append(data, '\n')); err != nil {
		_ = fh.Close() //nolint:gosec // G104: ошибка записи важнее
		return fmt.Errorf("-out: %w", err)
	}
	if err := fh.Close(); err != nil {
		return fmt.Errorf("-out: %w", err)
	}
	return nil
}
