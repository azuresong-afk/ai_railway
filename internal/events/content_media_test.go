package events

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Изображения запроса в содержимом события full (задача 6.13, ADR-0039).

var storedPNG = []byte("\x89PNG\r\n\x1a\nсинтетическое изображение")

// withImage — событие full с одним сохранённым изображением.
func withImage() *Event {
	e := withMedia()
	e.Storage = StorageFull
	e.Media[0].Stored = true
	e.Media[1].StoreSkipped = StoreSkipURL
	e.Content = &Content{Request: "Что на картинке?", Images: []ContentImage{
		{Location: "messages[0].content[1]", Format: "png", Data: storedPNG},
	}}
	return e
}

func TestValidateImagesOK(t *testing.T) {
	if err := withImage().Validate(); err != nil {
		t.Fatal(err)
	}
	// Очищенное — PNG или JPEG; только изображение без текста — тоже.
	e := withImage()
	e.Content.Request = ""
	e.Content.Images[0].Sanitized, e.Content.Images[0].Format = true, "jpeg"
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	// Ровно на пределах.
	e = withImage()
	e.Content.Images[0].Data = make([]byte, MaxStoredImageBytes)
	if err := e.Validate(); err != nil {
		t.Fatalf("на пределе изображения: %v", err)
	}
}

func TestValidateImagesErrors(t *testing.T) {
	cases := map[string]func(*Event){
		"режим masked":               func(e *Event) { e.Storage = StorageMasked },
		"тип события":                func(e *Event) { e.Type = TypeAgentMCP },
		"пустые байты":               func(e *Event) { e.Content.Images[0].Data = nil },
		"больше предела":             func(e *Event) { e.Content.Images[0].Data = make([]byte, MaxStoredImageBytes+1) },
		"формат":                     func(e *Event) { e.Content.Images[0].Format = "svg" },
		"очищенное не PNG и не JPEG": func(e *Event) { e.Content.Images[0].Sanitized, e.Content.Images[0].Format = true, "gif" },
		"нет места":                  func(e *Event) { e.Content.Images[0].Location = "" },
		"место не из media":          func(e *Event) { e.Content.Images[0].Location = "messages[9].content[9]" },
		"без stored в media":         func(e *Event) { e.Media[0].Stored = false },
		"stored без изображения":     func(e *Event) { e.Content.Images = nil },
		"формат не разобран":         func(e *Event) { e.Media[0].Format = "" },
		"stored и store_skipped":     func(e *Event) { e.Media[0].StoreSkipped = StoreSkipTooLarge },
		"неизвестная причина":        func(e *Event) { e.Media[1].StoreSkipped = "lost" },
		"повтор места": func(e *Event) {
			e.Content.Images = append(e.Content.Images, e.Content.Images[0])
			e.Media = append(e.Media, e.Media[0])
		},
		"больше предела события": func(e *Event) {
			e.Content.Images = nil
			e.Media = nil
			e.Decision.MediaUnchecked = false
			for i := range 2 {
				loc := "images[" + string(rune('0'+i)) + "]"
				e.Media = append(e.Media, MediaCheck{Location: loc, Mode: MediaModeSync, Checked: true, Format: "png", Stored: true})
				e.Content.Images = append(e.Content.Images, ContentImage{Location: loc, Format: "png", Data: make([]byte, MaxEventImageBytes/2+1)})
			}
		},
		"больше 16 изображений": func(e *Event) {
			e.Content.Images = nil
			e.Media = nil
			e.Decision.MediaUnchecked = false
			for i := range MaxStoredImages + 1 {
				loc := "images[" + strings.Repeat("1", i+1) + "]"
				e.Media = append(e.Media, MediaCheck{Location: loc, Mode: MediaModeSync, Checked: true, Format: "png", Stored: true})
				e.Content.Images = append(e.Content.Images, ContentImage{Location: loc, Format: "png", Data: storedPNG})
			}
		},
	}
	for name, mut := range cases {
		e := withImage()
		mut(e)
		if err := e.Validate(); err == nil {
			t.Errorf("%s: событие принято", name)
		}
	}
}

// В JSON байты — base64; в details (метаданные события) изображения нет.
func TestImagesNotInDetails(t *testing.T) {
	e := withImage()
	b, err := json.Marshal(e)
	if err != nil || !strings.Contains(string(b), `"images":[{"location":"messages[0].content[1]","format":"png","data":"`) {
		t.Fatalf("JSON события: %s %v", b, err)
	}
	d, err := json.Marshal(e.Details())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(d), `"images"`) || bytes.Contains(d, storedPNG) || !strings.Contains(string(d), `"stored":true`) {
		t.Fatalf("details: %s", d)
	}
	// Открытый текст event_content — без изображений.
	plain, err := MarshalContent(e.Content.textOnly())
	if err != nil || strings.Contains(string(plain), "images") {
		t.Fatalf("открытый текст содержимого: %s %v", plain, err)
	}
}

func TestDropImagesCopies(t *testing.T) {
	e := withImage()
	shared := e.Content
	media := e.Media
	e.DropImages(StoreSkipQueueFull)
	if e.ImageBytes() != 0 || e.Media[0].Stored || e.Media[0].StoreSkipped != StoreSkipQueueFull || e.Content.Request == "" {
		t.Fatalf("после DropImages: %+v %+v", e.Content, e.Media)
	}
	if len(shared.Images) != 1 || !media[0].Stored {
		t.Fatal("DropImages изменил общее содержимое")
	}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	// Без текста содержимое пропадает целиком.
	e = withImage()
	e.Content.Request = ""
	e.DropImages(StoreSkipQueueFull)
	if e.Content != nil {
		t.Fatalf("пустое содержимое осталось: %+v", e.Content)
	}
}

// Очередь шлюза держит изображения в пределах MaxImageBytes: сверх — событие
// уходит без изображения с отметкой queue_full; после отправки предел
// освобождается.
func TestQueueImageBudget(t *testing.T) {
	sink := &memSink{block: make(chan struct{})}
	budget := int64(2*len(storedPNG) + 1)
	q := NewQueue(sink, QueueConfig{Capacity: 10, BatchSize: 10, FlushEach: time.Hour, MaxImageBytes: budget})
	for i := range 3 {
		e := withImage()
		e.ID = "0190000000-img-" + string(rune('a'+i))
		if err := q.Enqueue(*e); err != nil {
			t.Fatal(err)
		}
	}
	if got := q.imageBytes.Load(); got != int64(2*len(storedPNG)) {
		t.Fatalf("в очереди байтов изображений %d", got)
	}
	close(sink.block)
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) != 3 {
		t.Fatalf("доставлено %d", len(sink.events))
	}
	if sink.events[0].ImageBytes() == 0 || sink.events[1].ImageBytes() == 0 || sink.events[2].ImageBytes() != 0 ||
		sink.events[2].Media[0].StoreSkipped != StoreSkipQueueFull {
		t.Fatalf("третье событие: %+v", sink.events[2].Media)
	}
	if got := q.imageBytes.Load(); got != 0 {
		t.Fatalf("после отправки в очереди байтов %d", got)
	}
}
