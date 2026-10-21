package api

import "net/http"

// DefaultCSP — политика содержимого по умолчанию (ТЗ, 6.9). Интерфейс обязан
// работать при ней: inline-скрипты и стили, внешние ресурсы запрещены.
const DefaultCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// SecurityHeaders добавляет заголовки безопасности ко всем ответам, в том
// числе к ошибкам и статике. Сервер работает только по TLS, поэтому HSTS
// выдаётся всегда.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", DefaultCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
