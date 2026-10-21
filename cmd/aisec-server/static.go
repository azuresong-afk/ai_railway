package main

import "net/http"

// staticFallback — обработчик статики веб-консоли для путей вне /api и /internal.
// Задача 2.21 заменяет тело на встроенную (embed) сборку фронтенда; пока
// статики нет и такие пути отвечают 404.
func staticFallback() http.Handler { return nil }
