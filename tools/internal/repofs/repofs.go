// Пакет repofs — общие правила обхода дерева репозитория для утилит проверки.
package repofs

// rootOnly — каталоги, которые пропускаются только в корне репозитория.
// Глубже Go собирает пакеты из каталогов с любыми именами, поэтому
// пропускать, например, internal/x/build/ нельзя: так обходились бы проверки.
var rootOnly = map[string]bool{".git": true, "vendor": true, "bin": true, "build": true, "node_modules": true}

// Skip сообщает, нужно ли пропустить каталог p (путь от корня, через «/»)
// с именем name. testdata пропускается на любой глубине: Go не собирает его
// как часть пакетов.
func Skip(p, name string) bool {
	if p == "." {
		return false
	}
	if name == "testdata" {
		return true
	}
	return p == name && rootOnly[name]
}
