module example.com/lintsample

go 1.27.0

require golang.org/x/crypto v0.0.0

// Заглушка вместо настоящего модуля: образец собирается без сети.
replace golang.org/x/crypto => ./stub/xcrypto
