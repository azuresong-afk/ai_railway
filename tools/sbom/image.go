package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// SBOM образа поставки (ADR-0019): тот же состав из бинарников, что у SBOM
// продукта, но предмет документа — образ контейнера. Образы собираются на
// scratch, поэтому пакетов ОС в них нет: кроме бинарников, в образе только
// манифест целостности и его подпись — они попадают в SBOM файлами с хешем.

const (
	imageRef = "image"
	// propImageBase — базовый образ (у образов поставки — scratch).
	propImageBase = "aisec:image_base"
	// propNativeSource — версия библиотеки C/C++ из реестра с коммитом исходников.
	propNativeSource = "aisec:native_source"
	// maxImageFile ограничивает размер дополнительного файла образа (файл
	// хешируется потоком; самый крупный — библиотека ONNX Runtime aisec-ml).
	maxImageFile = 512 << 20
)

// imageNameRe — ссылка на образ «репозиторий:тег» без digest: digest
// появляется только после сборки и в SBOM, который собирается до неё, не
// известен.
var imageNameRe = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// imageSpec — образ, для которого строится SBOM; пустое имя — SBOM продукта.
type imageSpec struct {
	Name  string   // «репозиторий:тег»
	Files []string // файлы образа помимо бинарников
	// Native — добавить библиотеки C/C++ из реестра (образ aisec-ml).
	Native bool
}

// fileList — повторяемый флаг -file.
type fileList []string

func (f *fileList) String() string     { return strings.Join(*f, ",") }
func (f *fileList) Set(v string) error { *f = append(*f, v); return nil }

// ImageFile — файл образа помимо бинарников.
type ImageFile struct {
	Name   string
	SHA256 string
}

// readImageFile читает файл образа и считает его хеш.
func readImageFile(path string, hasher aisecCrypto.Hasher) (ImageFile, error) {
	f, err := os.Open(path) //nolint:gosec // G304: пути к файлам выпуска задаёт Makefile
	if err != nil {
		return ImageFile{}, err
	}
	defer f.Close() //nolint:errcheck // файл открыт только для чтения
	h := hasher.New()
	n, err := io.Copy(h, io.LimitReader(f, maxImageFile+1))
	if err != nil {
		return ImageFile{}, err
	}
	if n > maxImageFile {
		return ImageFile{}, fmt.Errorf("%s больше %d байт", path, maxImageFile)
	}
	return ImageFile{Name: filepath.Base(path), SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// AsImage делает предметом документа образ name («репозиторий:тег»): корень
// зависимостей — образ, он содержит бинарники и файлы files. Серийный номер
// пересчитывается.
func AsImage(bom *BOM, name string, files []ImageFile, hasher aisecCrypto.Hasher) error {
	if !imageNameRe.MatchString(name) {
		return fmt.Errorf("образ %q: ожидается «репозиторий:тег» строчными латинскими буквами", name)
	}
	if len(bom.Dependencies) == 0 || bom.Dependencies[0].Ref != productRef {
		return errors.New("в документе нет корня зависимостей продукта")
	}
	i := strings.LastIndexByte(name, ':')
	repo, tag := name[:i], name[i+1:]
	seen := map[string]bool{}
	for _, c := range bom.Components {
		seen[c.BOMRef] = true
	}
	root := Dependency{Ref: imageRef, DependsOn: append([]string{}, bom.Dependencies[0].DependsOn...)}
	for _, f := range files {
		ref := "file:" + f.Name
		if seen[ref] {
			return fmt.Errorf("файл %s указан дважды", f.Name)
		}
		seen[ref] = true
		bom.Components = append(bom.Components, Component{
			Type: "file", BOMRef: ref, Name: f.Name, Version: bom.Metadata.Component.Version,
			Hashes: []Hash{{Alg: "SHA-256", Content: f.SHA256}},
		})
		root.DependsOn = append(root.DependsOn, ref)
	}
	sort.Strings(root.DependsOn)
	bom.Dependencies[0] = root
	bom.Metadata.Component = Component{
		Type: "container", BOMRef: imageRef, Name: repo, Version: tag,
		Description: productName + ": образ поставки",
		Properties:  []Property{{propImageBase, "scratch"}},
	}
	bom.SerialNumber = serialFor(bom, hasher)
	return nil
}
