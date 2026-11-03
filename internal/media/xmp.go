package media

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

// Разбор XMP (задача 5.43, DM-47): пакет RDF/XML читается потоковым
// разборщиком encoding/xml (без DTD и внешних сущностей) с пределами
// глубины, числа элементов и размера. Текст — значения свойств (содержимое
// элементов и атрибуты-свойства rdf:Description) вне служебных
// пространств имён: история правок, идентификаторы документов, параметры
// обработки и даты в детекторы не идут.

// errXMP — пакет XMP не разобран (или превысил пределы).
var errXMP = errors.New("aisec-media: пакет XMP не разобран")

// Пределы разбора XMP.
const (
	maxXMPBytes  = 256 << 10
	maxXMPDepth  = 32
	maxXMPTokens = 20_000
)

// xmpSkipNS — служебные пространства имён: структура RDF, оболочка,
// история и ссылки (идентификаторы), параметры Camera Raw.
var xmpSkipNS = map[string]bool{
	"http://www.w3.org/1999/02/22-rdf-syntax-ns#": true,
	"adobe:ns:meta/":                       true,
	"http://www.w3.org/XML/1998/namespace": true,
	"xmlns":                                true,
	"http://ns.adobe.com/xap/1.0/mm/":      true,
	"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#":  true,
	"http://ns.adobe.com/xap/1.0/sType/ResourceRef#":    true,
	"http://ns.adobe.com/xap/1.0/sType/Version#":        true,
	"http://ns.adobe.com/camera-raw-settings/1.0/":      true,
	"http://ns.adobe.com/xap/1.0/sType/Dimensions#":     true,
	"http://ns.adobe.com/photoshop/1.0/camera-profile/": true,
}

const rdfNS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"

// xmpProperty — имя свойства идёт в детекторы: не служебное и не дата.
func xmpProperty(n xml.Name) bool {
	return n.Local != "" && !xmpSkipNS[n.Space] && !strings.Contains(n.Local, "Date")
}

// parseXMP разбирает пакет и передаёт тексты свойств в add.
func parseXMP(b []byte, add func(string) bool) error {
	if len(b) > maxXMPBytes {
		return errXMP
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	// prop — для каждого открытого элемента: ближайшее свойство (не
	// элемент RDF) — его текст идёт в детекторы.
	var prop []bool
	for tokens := 0; ; tokens++ {
		if tokens > maxXMPTokens {
			return errXMP
		}
		tok, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return errXMP
		}
		switch el := tok.(type) {
		case xml.StartElement:
			if len(prop) >= maxXMPDepth {
				return errXMP
			}
			cur := false
			switch {
			case el.Name.Space == rdfNS && len(prop) > 0:
				cur = prop[len(prop)-1] // rdf:Alt, rdf:Seq, rdf:li — внутри свойства
			case el.Name.Space != rdfNS:
				cur = xmpProperty(el.Name)
			}
			prop = append(prop, cur)
			if el.Name.Space == rdfNS && el.Name.Local == "Description" || el.Name.Space != rdfNS {
				// Краткая форма: свойства — атрибуты.
				for _, a := range el.Attr {
					if a.Name.Space != rdfNS && xmpProperty(a.Name) && !add(a.Value) {
						return nil
					}
				}
			}
		case xml.EndElement:
			if len(prop) > 0 {
				prop = prop[:len(prop)-1]
			}
		case xml.CharData:
			if len(prop) > 0 && prop[len(prop)-1] && !add(string(el)) {
				return nil
			}
		}
	}
}
