package media

import (
	"math"
	"slices"
)

// Геометрия строк OCR (задача 5.42, ADR-0033): связные области бинарной
// карты детектора, выпуклая оболочка, прямоугольник наименьшей площади и
// его расширение вдоль своих осей. Свой код по описанию алгоритмов (как в
// эксперименте 5.40 на numpy); из PaddleOCR, RapidOCR и OpenCV ничего не
// взято.

type point struct{ x, y float64 }

func (p point) add(q point) point    { return point{p.x + q.x, p.y + q.y} }
func (p point) sub(q point) point    { return point{p.x - q.x, p.y - q.y} }
func (p point) mul(k float64) point  { return point{p.x * k, p.y * k} }
func (p point) dot(q point) float64  { return p.x*q.x + p.y*q.y }
func (p point) dist(q point) float64 { return math.Hypot(p.x-q.x, p.y-q.y) }
func cross(o, a, b point) float64    { return (a.x-o.x)*(b.y-o.y) - (a.y-o.y)*(b.x-o.x) }
func (p point) less(q point) bool    { return p.x < q.x || (p.x == q.x && p.y < q.y) }
func (p point) equal(q point) bool   { return p.x == q.x && p.y == q.y }

// quad — четыре угла строки: левый верхний, правый верхний, правый
// нижний, левый нижний.
type quad [4]point

// component — связная область карты: точки (x, y) и средняя вероятность.
type component struct {
	pts   []point
	score float64
}

// components — связные области (4-связность) карты prob [h×w] выше порога
// thresh; не больше limit областей (остальные отбрасываются). Обход —
// своим стеком, без рекурсии.
func components(prob []float32, h, w int, thresh float32, limit int) []component {
	seen := make([]bool, len(prob))
	var out []component
	var stack []int
	for start, v := range prob {
		if v <= thresh || seen[start] {
			continue
		}
		if len(out) >= limit {
			break
		}
		seen[start] = true
		stack = append(stack[:0], start)
		var c component
		var sum float64
		for len(stack) > 0 {
			i := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			y, x := i/w, i%w
			c.pts = append(c.pts, point{float64(x), float64(y)})
			sum += float64(prob[i])
			for _, n := range [4]int{i - w, i + w, i - 1, i + 1} {
				switch {
				case n < 0 || n >= len(prob):
					continue
				case (n == i-1 && x == 0) || (n == i+1 && x == w-1):
					continue
				}
				if prob[n] > thresh && !seen[n] {
					seen[n] = true
					stack = append(stack, n)
				}
			}
		}
		c.score = sum / float64(len(c.pts))
		out = append(out, c)
	}
	return out
}

// hull — выпуклая оболочка (монотонная цепь Эндрю), против часовой
// стрелки; повторы точек удаляются.
func hull(pts []point) []point {
	p := slices.Clone(pts)
	slices.SortFunc(p, func(a, b point) int {
		switch {
		case a.less(b):
			return -1
		case b.less(a):
			return 1
		}
		return 0
	})
	p = slices.CompactFunc(p, point.equal)
	if len(p) < 3 {
		return p
	}
	half := func(seq []point) []point {
		var out []point
		for _, q := range seq {
			for len(out) >= 2 && cross(out[len(out)-2], out[len(out)-1], q) <= 0 {
				out = out[:len(out)-1]
			}
			out = append(out, q)
		}
		return out[:len(out)-1]
	}
	rev := slices.Clone(p)
	slices.Reverse(rev)
	return append(half(p), half(rev)...)
}

// rect — прямоугольник с осями u (единичный вектор) и v ⟂ u: проекции
// точек на оси — [a0, a1] и [b0, b1].
type rect struct {
	u, v           point
	a0, a1, b0, b1 float64
}

func (r rect) corners() quad {
	c := func(a, b float64) point { return r.u.mul(a).add(r.v.mul(b)) }
	return quad{c(r.a0, r.b0), c(r.a1, r.b0), c(r.a1, r.b1), c(r.a0, r.b1)}
}

// minAreaRect — прямоугольник наименьшей площади вокруг точек: одна из
// сторон лежит на ребре выпуклой оболочки (вращающиеся калиперы перебором
// рёбер). Меньше трёх точек оболочки — прямоугольник по осям.
func minAreaRect(pts []point) rect {
	hp := hull(pts)
	if len(hp) < 3 {
		r := rect{u: point{1, 0}, v: point{0, 1}, a0: math.Inf(1), a1: math.Inf(-1), b0: math.Inf(1), b1: math.Inf(-1)}
		for _, p := range pts {
			r.a0, r.a1 = math.Min(r.a0, p.x), math.Max(r.a1, p.x)
			r.b0, r.b1 = math.Min(r.b0, p.y), math.Max(r.b1, p.y)
		}
		return r
	}
	var best rect
	bestArea := math.Inf(1)
	for i := range hp {
		e := hp[(i+1)%len(hp)].sub(hp[i])
		n := math.Hypot(e.x, e.y)
		if n == 0 {
			continue
		}
		u := e.mul(1 / n)
		v := point{-u.y, u.x}
		r := rect{u: u, v: v, a0: math.Inf(1), a1: math.Inf(-1), b0: math.Inf(1), b1: math.Inf(-1)}
		for _, p := range hp {
			a, b := p.dot(u), p.dot(v)
			r.a0, r.a1 = math.Min(r.a0, a), math.Max(r.a1, a)
			r.b0, r.b1 = math.Min(r.b0, b), math.Max(r.b1, b)
		}
		if area := (r.a1 - r.a0) * (r.b1 - r.b0); area < bestArea {
			best, bestArea = r, area
		}
	}
	return best
}

// unclip расширяет прямоугольник вдоль своих осей на d = S·k/L (S —
// площадь, L — периметр): так PaddleOCR возвращает рамке поля, срезанные
// при обучении детектора. Для прямоугольника это то же, что смещение
// многоугольника со скруглением и новый прямоугольник наименьшей площади
// вокруг него, поэтому pyclipper не нужен (ADR-0033, «Последствия»).
func (r rect) unclip(k float64) rect {
	e1, e2 := r.a1-r.a0, r.b1-r.b0
	d := e1 * e2 * k / (2 * (e1 + e2))
	r.a0, r.a1, r.b0, r.b1 = r.a0-d, r.a1+d, r.b0-d, r.b1+d
	return r
}

// order — углы по порядку чтения: левый верхний (наименьшая сумма x+y),
// правый верхний (наименьшая y−x), правый нижний, левый нижний.
func order(q quad) quad {
	var out quad
	pick := func(key func(point) float64, maxi bool) point {
		best := q[0]
		for _, p := range q[1:] {
			if k, kb := key(p), key(best); (maxi && k > kb) || (!maxi && k < kb) {
				best = p
			}
		}
		return best
	}
	sum := func(p point) float64 { return p.x + p.y }
	diff := func(p point) float64 { return p.y - p.x }
	out[0], out[1], out[2], out[3] = pick(sum, false), pick(diff, false), pick(sum, true), pick(diff, true)
	return out
}

// bounds — рамка по осям вокруг углов, прижатая к растру w×h.
func (q quad) bounds(w, h int) (x0, y0, x1, y1 float64) {
	x0, y0, x1, y1 = math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)
	for _, p := range q {
		x0, x1 = math.Min(x0, p.x), math.Max(x1, p.x)
		y0, y1 = math.Min(y0, p.y), math.Max(y1, p.y)
	}
	return clampF(x0, 0, float64(w)), clampF(y0, 0, float64(h)), clampF(x1, 0, float64(w)), clampF(y1, 0, float64(h))
}
