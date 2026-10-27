package argschema

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// x-aisec-path-prefix (ADR-0023, раздел 3): путь в аргументе — только внутри
// разрешённых каталогов. Путь не нормализуется, а должен быть уже
// нормализованным: сегменты «..» и «.» и «//» — отказ. Лексическая
// нормализация расходится с ядром при символических ссылках
// (/data/a/link/../../x при link → /data открывает /x), поэтому fail-closed:
//   - путь не абсолютный — отказ;
//   - «\», NUL, «%» и другие управляющие символы — отказ (обход через
//     кодирование и разное понимание разделителя);
//   - путь вне всех префиксов — отказ;
//   - префикс сравнивается по границе каталога: /data/reports/ не
//     пропускает /data/reports-old/.

// Причины отказа по пути — без самого значения (аргументы — содержимое).
var (
	errPathRelative = errors.New("путь не абсолютный")
	errPathChars    = errors.New("путь содержит «\\», «%» или управляющие символы")
	errPathOutside  = errors.New("путь вне разрешённых каталогов")
	errPathNotClean = errors.New("путь содержит сегменты «..», «.» или «//»")
)

// badPathChar — символ, недопустимый в пути аргумента и префиксе.
func badPathChar(r rune) bool { return r == '\\' || r == '%' || r < 0x20 || r == 0x7f }

func pathPrefixes(x Value) ([]string, error) {
	list, err := stringList(x, MaxPathPrefixes, true)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, p := range list {
		dir, err := cleanPrefix(p)
		if err != nil {
			return nil, err
		}
		out = append(out, dir)
	}
	return out, nil
}

// cleanPrefix — префикс в виде каталога без завершающей «/» («/» для корня).
// Префикс уже нормализован: запись с «..» или «//» — ошибка, а не молчаливое
// исправление.
func cleanPrefix(p string) (string, error) {
	if p == "" || len(p) > MaxPathPrefixLen || strings.ContainsFunc(p, badPathChar) || !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("префикс — абсолютный путь до %d байт без «\\», «%%» и управляющих символов", MaxPathPrefixLen)
	}
	dir := strings.TrimSuffix(p, "/")
	if dir == "" {
		return "/", nil
	}
	if path.Clean(dir) != dir {
		return "", errors.New("префикс — нормализованный путь без «..», «.» и «//»")
	}
	return dir, nil
}

// checkPath — путь s внутри одного из префиксов dirs.
func checkPath(s string, dirs []string) error {
	if strings.ContainsFunc(s, badPathChar) {
		return errPathChars
	}
	if !strings.HasPrefix(s, "/") {
		return errPathRelative
	}
	clean := s
	if len(clean) > 1 {
		clean = strings.TrimSuffix(clean, "/")
	}
	if path.Clean(clean) != clean {
		return errPathNotClean
	}
	for _, d := range dirs {
		if d == "/" || clean == d || strings.HasPrefix(clean, d+"/") {
			return nil
		}
	}
	return errPathOutside
}
