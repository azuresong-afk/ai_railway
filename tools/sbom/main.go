// Команда sbom формирует SBOM продукта в формате CycloneDX 1.6 JSON (ТЗ, 8.6).
//
// Состав берётся из самих собранных бинарников (debug/buildinfo): в SBOM
// попадает ровно то, что вошло в поставку. Сведения о компонентах —
// лицензия, репозиторий, свойства GOST:attack_surface, GOST:security_function,
// GOST:provided_by — из docs/cert/components.yaml. Компонент без записи
// в реестре — ошибка.
//
// SBOM воспроизводим: время берётся из флага (в Makefile — время последнего
// коммита), серийный номер выводится из содержимого.
package main

import (
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/tools/internal/components"
)

// maxBinary ограничивает размер анализируемого бинарника.
const maxBinary = 512 << 20

func main() {
	registry := flag.String("registry", "docs/cert/components.yaml", "реестр компонентов")
	out := flag.String("out", "build/sbom/aisec.cdx.json", "куда записать SBOM")
	version := flag.String("version", "dev", "версия продукта")
	timestamp := flag.String("timestamp", "", "время формирования (RFC 3339), для воспроизводимости")
	check := flag.String("check", "", "только проверить готовый SBOM на обязательные поля и выйти")
	goSum := flag.String("gosum", "go.sum", "go.sum модуля: хеши модулей для сборки с vendor/, где их нет в сведениях о сборке")
	flag.Parse()

	var err error
	if *check != "" {
		err = checkFile(*check)
	} else {
		err = run(*registry, *goSum, *out, *version, *timestamp, flag.Args())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
}

func run(registryPath, goSumPath, out, version, timestamp string, binaries []string) error {
	if len(binaries) == 0 {
		return errors.New("не указаны бинарники")
	}
	ts := time.Unix(0, 0).UTC()
	if timestamp != "" {
		t, err := time.Parse(time.RFC3339, timestamp)
		if err != nil {
			return fmt.Errorf("timestamp: %w", err)
		}
		ts = t.UTC()
	}
	f, err := os.Open(registryPath) //nolint:gosec // G304: путь к реестру задаёт Makefile
	if err != nil {
		return err
	}
	reg, err := components.Parse(f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%s: %w", registryPath, err)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	hasher, err := p.Hasher()
	if err != nil {
		return err
	}
	sums, err := readGoSum(goSumPath)
	if err != nil {
		return err
	}
	var bins []Binary
	for _, path := range binaries {
		b, err := readBinary(path, hasher)
		if err != nil {
			return err
		}
		fillSums(&b, sums)
		bins = append(bins, b)
	}
	bom, err := Build(reg, bins, version, ts, hasher)
	if err != nil {
		return err
	}
	if err := Check(bom); err != nil {
		return err
	}
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "sbom: %s — компонентов %d, бинарников %d\n", out, len(bom.Components)-len(bins), len(bins))
	return err
}

// Binary — сведения о собранном бинарнике.
type Binary struct {
	Name      string
	SHA256    string
	GoVersion string
	Deps      []Dep
}

// Dep — модуль, вошедший в бинарник.
type Dep struct {
	Path, Version, Sum string
}

func readBinary(path string, hasher aisecCrypto.Hasher) (Binary, error) {
	f, err := os.Open(path) //nolint:gosec // G304: пути к собранным бинарникам задаёт Makefile
	if err != nil {
		return Binary{}, err
	}
	defer f.Close() //nolint:errcheck // файл открыт только для чтения
	info, err := f.Stat()
	if err != nil {
		return Binary{}, err
	}
	if info.Size() > maxBinary {
		return Binary{}, fmt.Errorf("%s больше %d байт", path, maxBinary)
	}
	h := hasher.New()
	if _, err := io.Copy(h, f); err != nil {
		return Binary{}, err
	}
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return Binary{}, fmt.Errorf("%s: сведения о сборке: %w", path, err)
	}
	b := Binary{Name: filepath.Base(path), SHA256: hex.EncodeToString(h.Sum(nil)), GoVersion: bi.GoVersion}
	for _, d := range bi.Deps {
		if d.Replace != nil {
			return Binary{}, fmt.Errorf("%s: модуль %s заменён (%s) — замена требует отдельного решения", path, d.Path, d.Replace.Path)
		}
		b.Deps = append(b.Deps, Dep{Path: d.Path, Version: d.Version, Sum: d.Sum})
	}
	return b, nil
}

// maxGoSum ограничивает размер go.sum.
const maxGoSum = 4 << 20

// readGoSum читает хеши модулей из go.sum: «модуль версия» → «h1:…».
// Строки go.mod-хешей («версия/go.mod») не нужны: в бинарник входит код модуля.
func readGoSum(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: путь к go.sum задаёт Makefile
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // файл открыт только для чтения
	data, err := io.ReadAll(io.LimitReader(f, maxGoSum+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxGoSum {
		return nil, fmt.Errorf("%s больше %d байт", path, maxGoSum)
	}
	sums := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s:%d: ожидается «модуль версия хеш»", path, i+1)
		}
		if strings.HasSuffix(fields[1], "/go.mod") {
			continue
		}
		sums[fields[0]+" "+fields[1]] = fields[2]
	}
	return sums, nil
}

// fillSums дополняет хеши модулей из go.sum. При сборке с -mod=vendor Go не
// записывает хеш в сведения о сборке. Это заявленный хеш модуля, а не хеш
// кода из vendor/: сборка сверяет vendor/modules.txt только с go.mod, а
// содержимое vendor/ с go.sum — только go mod vendor при вендоринге.
// Неизменность vendor/ проверяется отдельно (план этапа 1, задача 1.28).
func fillSums(b *Binary, sums map[string]string) {
	for i, d := range b.Deps {
		if d.Sum == "" {
			b.Deps[i].Sum = sums[d.Path+" "+d.Version]
		}
	}
}

// maxSBOM ограничивает размер проверяемого SBOM.
const maxSBOM = 32 << 20

// checkFile проверяет готовый SBOM на обязательные поля (Check).
func checkFile(path string) error {
	data, err := readSBOM(path)
	if err != nil {
		return err
	}
	bom, err := ParseBOM(data)
	if err != nil {
		return err
	}
	return Check(bom)
}

func readSBOM(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSBOM {
		return nil, fmt.Errorf("%s больше %d байт", path, maxSBOM)
	}
	return os.ReadFile(path) //nolint:gosec // G304: путь к SBOM задаёт Makefile
}

// ParseBOM разбирает документ CycloneDX JSON; неизвестные поля пропускаются.
func ParseBOM(data []byte) (*BOM, error) {
	if len(data) > maxSBOM {
		return nil, fmt.Errorf("SBOM больше %d байт", maxSBOM)
	}
	var bom BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("разбор SBOM: %w", err)
	}
	return &bom, nil
}
