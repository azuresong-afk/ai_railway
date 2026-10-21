package integrity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Source — набор файлов для манифеста: каталог на диске сборочной машины и
// вид. Files — явный список имён (бинарники); пусто — все обычные файлы
// каталога: с подкаталогами при Recursive, иначе только подходящие под Glob.
type Source struct {
	Kind      Kind
	Dir       string
	Files     []string
	Glob      string
	Recursive bool
}

// BuildInput — параметры манифеста.
type BuildInput struct {
	Version string
	Created time.Time
	Sources []Source
}

// Build считает хеши файлов и собирает манифест (make manifest). Ссылки и
// не обычные файлы — ошибка: их содержимое на целевой машине другое.
func Build(p aisecCrypto.Provider, in BuildInput) (*Manifest, error) {
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	m := &Manifest{Format: FormatV1, Version: in.Version, Profile: p.Name(), HashAlg: h.Name(), Created: in.Created.UTC()}
	for _, src := range in.Sources {
		prefix, ok := kindPrefix[src.Kind]
		if !ok {
			return nil, fmt.Errorf("манифест: неизвестный вид %q", src.Kind)
		}
		names, err := sourceFiles(src)
		if err != nil {
			return nil, fmt.Errorf("манифест: %s: %w", src.Dir, err)
		}
		root, err := os.OpenRoot(src.Dir)
		if err != nil {
			return nil, fmt.Errorf("манифест: %w", err)
		}
		for _, name := range names {
			sum, size, err := hashRootFile(root, name, h)
			if err != nil {
				_ = root.Close() //nolint:gosec // G104: исходная ошибка важнее, каталог только читался
				return nil, fmt.Errorf("манифест: %s/%s: %w", src.Dir, name, err)
			}
			m.Files = append(m.Files, Entry{Path: prefix + name, Kind: src.Kind, Size: size, Hash: hex.EncodeToString(sum)})
		}
		if err := root.Close(); err != nil {
			return nil, err
		}
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

func sourceFiles(src Source) ([]string, error) {
	if len(src.Files) > 0 {
		return src.Files, nil
	}
	var out []string
	err := fs.WalkDir(os.DirFS(src.Dir), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && !src.Recursive {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: не обычный файл", p)
		}
		if src.Glob != "" {
			ok, err := path.Match(src.Glob, p)
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("нет файлов")
	}
	return out, nil
}

// hashRootFile хеширует обычный файл внутри root; ссылка — ошибка.
func hashRootFile(root *os.Root, name string, h aisecCrypto.Hasher) ([]byte, int64, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, errors.New("не обычный файл")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close() //nolint:errcheck // файл только читается
	return hashReader(f, MaxFileSize, h)
}

// hashReader хеширует не больше limit байт; больше — ошибка.
func hashReader(r io.Reader, limit int64, h aisecCrypto.Hasher) ([]byte, int64, error) {
	hh := h.New()
	n, err := io.Copy(hh, io.LimitReader(r, limit+1))
	if err != nil {
		return nil, 0, err
	}
	if n > limit {
		return nil, 0, fmt.Errorf("файл больше %d байт", limit)
	}
	return hh.Sum(nil), n, nil
}
