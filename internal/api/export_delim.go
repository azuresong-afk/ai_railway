package api

import "github.com/azuresong-afk/ai_railway/internal/events"

// delimName — имя разделителя CSV для журнала аудита; для не-CSV пусто.
func delimName(delim rune, format string) string {
	if format != events.FormatCSV {
		return ""
	}
	if delim == events.DelimComma {
		return "comma"
	}
	return "semicolon"
}
