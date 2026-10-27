package argschema

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// x-aisec-domains (ADR-0023, раздел 3): адрес e-mail или URL в аргументе —
// только в разрешённых доменах. Совпадение точное или по суффиксу «.домен»:
// example.ru пропускает mail.example.ru, но не badexample.ru. Разбор
// намеренно узкий (fail-closed): значение, которое можно прочесть двумя
// способами (несколько «@», имя пользователя в URL, «\», пробелы, не-ASCII в
// имени узла), отвергается.

// MaxDomainLen — байт в имени домена (RFC 1035).
const MaxDomainLen = 253

// localRe — локальная часть адреса e-mail: dot-atom RFC 5322 без «/», «:»,
// «?», «#», «%», скобок — иначе строку можно прочесть как URL другого узла
// (//evil.ru/x@good.ru).
var localRe = regexp.MustCompile(`^[A-Za-z0-9!$&'*+=^_{|}~-]+(\.[A-Za-z0-9!$&'*+=^_{|}~-]+)*$`)

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Причины отказа по домену — без самого значения.
var (
	errDomainFormat  = errors.New("ожидается адрес e-mail или URL http(s)://")
	errDomainOutside = errors.New("домен вне разрешённых")
)

func domainList(x Value) ([]string, error) {
	list, err := stringList(x, MaxDomains, true)
	if err != nil {
		return nil, err
	}
	for _, d := range list {
		if len(d) > MaxDomainLen || !domainRe.MatchString(d) {
			return nil, fmt.Errorf("домен %q — имя в нижнем регистре латиницей (IDN — в записи punycode)", clip(d))
		}
	}
	return list, nil
}

// hostOf — имя узла из адреса e-mail или URL в нижнем регистре.
func hostOf(s string) (string, error) {
	if s == "" || strings.ContainsFunc(s, func(r rune) bool { return r == '\\' || unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return "", errDomainFormat
	}
	var host string
	switch {
	case strings.Contains(s, "://"):
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.Opaque != "" {
			return "", errDomainFormat
		}
		host = u.Hostname()
	case strings.Count(s, "@") == 1:
		at := strings.IndexByte(s, '@')
		if local := s[:at]; len(local) > 64 || !localRe.MatchString(local) {
			return "", errDomainFormat
		}
		host = s[at+1:]
	default:
		return "", errDomainFormat
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if len(host) > MaxDomainLen || !domainRe.MatchString(host) {
		return "", errDomainFormat
	}
	return host, nil
}

// checkDomain — адрес s в одном из доменов list.
func checkDomain(s string, list []string) error {
	host, err := hostOf(s)
	if err != nil {
		return err
	}
	for _, d := range list {
		if host == d || strings.HasSuffix(host, "."+d) {
			return nil
		}
	}
	return errDomainOutside
}
