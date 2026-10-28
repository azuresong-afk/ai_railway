package sysstatus

import "github.com/azuresong-afk/ai_railway/internal/shadowai"

// shadowAISyslog — раздел «Приём журналов по syslog» (теневой ИИ, задача
// 4.23): счётчики отказов и разрывов сверх пределов слушателя, строк и
// записи сводок. Слушатель выключен — раздела нет.
func (s *Service) shadowAISyslog(c *collected) {
	if s.o.ShadowAISyslog == nil {
		return
	}
	if st := s.o.ShadowAISyslog(); st.Enabled {
		c.st.ShadowAISyslog = &st
	}
}

// ShadowAISyslogStats — тип раздела (для документации API).
type ShadowAISyslogStats = shadowai.SyslogStats
