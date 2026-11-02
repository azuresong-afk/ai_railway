package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/cliclient"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/inventory"
	"github.com/azuresong-afk/ai_railway/internal/modelscan"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Сканер моделей на узле заказчика (ТЗ 5.12, DM-27–DM-29; задачи 5.21 и
// 5.22 этапа 5, ADR-0029, п. 4 и дополнение 1). Файлы модели читаются
// здесь, на сервер уходит отчёт без весов: пути, размеры, форматы, хеши
// SHA-256, находки и шаблоны чата. О запрете модели решает сервер.

// errModelBlocked — отчёт запретил модель или хеши не совпали (код выхода 3).
var errModelBlocked = errors.New("модель не прошла проверку")

// scanHostRe — имя узла в отчёте (как проверяет сервер).
var scanHostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// modelsFlags — общие флаги models scan и verify.
type modelsFlags struct {
	server, ca, tokenFile, model, host, profile string
	timeout                                     time.Duration
}

func (f *modelsFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.server, "server", "", "адрес сервера управления: https://хост[:порт]")
	fs.StringVar(&f.ca, "ca", "", "корневой сертификат сервера (PEM): доверие — только ему")
	fs.StringVar(&f.tokenFile, "token-file", "", "файл с токеном API с правом models.report (права 0600 или 0400)")
	fs.StringVar(&f.model, "model", "", "ID модели в реестре ИИ")
	fs.StringVar(&f.host, "host", "", "имя узла в отчёте; пусто — имя хоста")
	fs.StringVar(&f.profile, "crypto-profile", aisecCrypto.ProfileStandard, "криптопрофиль TLS: standard или gost")
	fs.DurationVar(&f.timeout, "timeout", cliclient.DefaultTimeout, "срок одного запроса к серверу")
}

func (f *modelsFlags) check(fs *flag.FlagSet) (string, error) {
	if fs.NArg() != 1 {
		return "", errors.New("укажите один путь: каталог или файл модели")
	}
	if f.server == "" || f.ca == "" || f.tokenFile == "" || f.model == "" {
		return "", errors.New("обязательны -server, -ca, -token-file и -model")
	}
	if _, err := store.ParseUUID(f.model); err != nil {
		return "", errors.New("-model: ID модели из реестра ИИ (UUID)")
	}
	if f.timeout <= 0 || f.timeout > 10*time.Minute {
		return "", errors.New("-timeout: от 1 с до 10 мин")
	}
	if f.host == "" {
		h, err := os.Hostname()
		if err != nil {
			return "", fmt.Errorf("имя узла: %w; задайте -host", err)
		}
		f.host = h
	}
	if !scanHostRe.MatchString(f.host) {
		return "", errors.New("-host: латинские буквы, цифры, «.», «-», «_», до 253 символов")
	}
	return fs.Arg(0), nil
}

func (f *modelsFlags) client() (*cliclient.Client, aisecCrypto.Hasher, error) {
	p, err := aisecCrypto.New(f.profile)
	if err != nil {
		return nil, nil, fmt.Errorf("-crypto-profile: %w", err)
	}
	c, err := cliclient.New(cliclient.Options{Server: f.server, CAFile: f.ca, TokenFile: f.tokenFile, Provider: p, Timeout: f.timeout})
	if err != nil {
		return nil, nil, err
	}
	// Хеш файлов модели — SHA-256 в обоих профилях (ADR-0029, п. 1).
	sp, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return nil, nil, err
	}
	h, err := sp.Hasher()
	if err != nil {
		return nil, nil, err
	}
	return c, h, nil
}

// modelsCmd — aisec-cli models scan|verify.
func modelsCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "scan":
			return modelsScan(args[1:], stdout, stderr)
		case "verify":
			return modelsVerify(args[1:], stdout, stderr)
		}
	}
	return errors.New("подкоманда: scan или verify")
}

func modelsScan(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("models scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f modelsFlags
	f.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := f.check(fs)
	if err != nil {
		return err
	}
	c, h, err := f.client()
	if err != nil {
		return err
	}
	rep, err := modelscan.New(modelscan.Limits{}).WithHash(h.New).ScanPath(root)
	if err != nil {
		return fmt.Errorf("проверка файлов: %w", err)
	}
	in := reportInput(inventory.ReportScan, f.host, rep)
	return sendReport(c, f.model, in, stdout)
}

func modelsVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("models verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f modelsFlags
	f.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := f.check(fs)
	if err != nil {
		return err
	}
	c, h, err := f.client()
	if err != nil {
		return err
	}
	// Эталон — с сервера тем же токеном: локальная сверка для оператора,
	// решение по отчёту принимает сервер.
	var ref inventory.Reference
	if err := c.Do(context.Background(), "GET", "/api/v1/inventory/models/"+f.model+"/reference", nil, "", &ref); err != nil {
		return fmt.Errorf("эталонные хеши: %w", err)
	}
	rep, err := modelscan.New(modelscan.Limits{}).WithHash(h.New).HashPath(root)
	if err != nil {
		return fmt.Errorf("хеши файлов: %w", err)
	}
	printLocalDiff(stdout, ref, rep)
	in := reportInput(inventory.ReportVerify, f.host, rep)
	return sendReport(c, f.model, in, stdout)
}

// printLocalDiff — расхождения с эталоном на узле (до отправки отчёта).
func printLocalDiff(w io.Writer, ref inventory.Reference, rep *modelscan.Report) {
	got := make(map[string]modelscan.FileReport, len(rep.Files))
	for _, f := range rep.Files {
		got[f.Path] = f
	}
	n := 0
	for _, r := range ref.Files {
		g, ok := got[r.Path]
		switch {
		case !ok:
			say(w, "Нет файла: %s (%s)\n", safeText(r.Path), r.Role)
		case g.SHA256 != r.SHA256 || g.Size != r.Size:
			say(w, "Не совпадает: %s (%s)\n", safeText(r.Path), r.Role)
		default:
			continue
		}
		n++
	}
	say(w, "Эталонных файлов в реестре: %d, на узле: %d, расхождений с эталоном: %d\n", len(ref.Files), len(rep.Files), n)
}

// reportInput — отчёт для сервера из итога сканера.
func reportInput(kind, host string, rep *modelscan.Report) inventory.ReportInput {
	in := inventory.ReportInput{Kind: kind, Host: host, ScannerVersion: scannerVersion(), Files: make([]inventory.ReportFile, 0, len(rep.Files)),
		Truncated: rep.Truncated}
	for _, f := range rep.Files {
		rf := inventory.ReportFile{Path: f.Path, Size: f.Size, Symlink: f.Symlink, SHA256: f.SHA256}
		if kind == inventory.ReportScan {
			rf.Format, rf.Tensors, rf.FindingsTruncated = string(f.Format), f.Tensors, f.FindingsCut
			for _, x := range f.Findings {
				rf.Findings = append(rf.Findings, inventory.ReportFinding{Code: x.Code, Severity: string(x.Severity), Detail: clip(x.Detail)})
			}
			for _, t := range f.ChatTemplates {
				rf.ChatTemplates = append(rf.ChatTemplates, inventory.ReportTemplate{Source: t.Source, Name: t.Name, Text: t.Text})
			}
		}
		in.Files = append(in.Files, rf)
	}
	if kind == inventory.ReportScan {
		for _, x := range rep.Findings {
			in.Findings = append(in.Findings, inventory.ReportFinding{Code: x.Code, Severity: string(x.Severity), Detail: clip(x.Detail)})
		}
	}
	return in
}

// clip — пояснение находки в пределе сервера (байты, по границе символа).
func clip(s string) string {
	if len(s) <= inventory.MaxFindingDetail {
		return s
	}
	return strings.ToValidUTF8(s[:inventory.MaxFindingDetail], "")
}

func scannerVersion() string {
	if version == "" {
		return "dev"
	}
	return version
}

// scanResult — ответ сервера на отчёт (поля ScanReportResult API).
type scanResult struct {
	ID            string   `json:"id"`
	Verdict       string   `json:"verdict"`
	Hashes        string   `json:"hashes"`
	Templates     string   `json:"templates"`
	Files         int      `json:"files"`
	Findings      int      `json:"findings"`
	Blocked       bool     `json:"blocked"`
	BlockReasons  []string `json:"block_reasons"`
	MismatchTotal int      `json:"mismatch_total"`
	ModelStatus   string   `json:"model_status"`
}

func sendReport(c *cliclient.Client, model string, in inventory.ReportInput, stdout io.Writer) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if len(body) > inventory.MaxReportBody {
		return fmt.Errorf("отчёт больше %d МиБ: проверьте модель по частям (подкаталогами)", inventory.MaxReportBody>>20)
	}
	var res scanResult
	if err := c.Do(context.Background(), "POST", "/api/v1/inventory/models/"+model+"/scan-reports", body, "application/json", &res); err != nil {
		return fmt.Errorf("отправка отчёта: %w", err)
	}
	say(stdout, "Отчёт %s принят сервером %s: файлов %d, находок %d\n", safeText(res.ID), c.Server(), res.Files, res.Findings)
	say(stdout, "Итог: %s; хеши: %s; шаблоны чата: %s; расхождений с реестром: %d\n", safeText(res.Verdict), safeText(res.Hashes),
		safeText(res.Templates), res.MismatchTotal)
	if len(res.BlockReasons) > 0 {
		say(stdout, "Причины запрета: %s\n", safeText(strings.Join(res.BlockReasons, ", ")))
	}
	say(stdout, "Состояние модели: %s\n", safeText(res.ModelStatus))
	if res.ModelStatus == inventory.StatusBlocked {
		say(stdout, "Модель запрещена и исключена из пакета шлюзов: запрет снимает администратор безопасности в консоли.\n")
	}
	if res.Verdict == inventory.VerdictBlock || res.ModelStatus == inventory.StatusBlocked {
		return errModelBlocked
	}
	return nil
}

// safeText — строка для терминала без управляющих символов.
func safeText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
}
