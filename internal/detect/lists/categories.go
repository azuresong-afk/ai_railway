package lists

import "slices"

// Categories — категории находок по спискам этого детектора: «lists.» и
// категория списка (detect.Categorizer). У детектора приложения — вместе с
// категориями его списков.
func (d *Detector) Categories() []string {
	var out []string
	for _, li := range d.c.lists {
		if c := "lists." + li.category; !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}
