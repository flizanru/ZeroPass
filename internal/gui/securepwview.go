package gui

import (
	"unicode/utf8"

	"gioui.org/layout"
	"gioui.org/widget/material"
	"github.com/awnumar/memguard"
)

type secureRuneLayout func(layout.Context, *material.Theme, string) layout.Dimensions

type securePWView struct {
	list       layout.List
	layoutRune secureRuneLayout
}

// layout renders one rune per label. Gio's text/lru.go:152 uses the complete
// string as an LRU key, so passing a whole password to a material.Label would
// retain the immutable password in the ordinary Go heap long after it is hidden.
func (v *securePWView) layout(gtx layout.Context, th *material.Theme, buf *memguard.LockedBuffer) layout.Dimensions {
	if buf == nil || !buf.IsAlive() {
		return layout.Dimensions{}
	}
	if v.layoutRune == nil {
		v.layoutRune = func(gtx layout.Context, th *material.Theme, text string) layout.Dimensions {
			return material.Body1(th, text).Layout(gtx)
		}
	}
	v.list.Axis = layout.Horizontal
	runes := utf8.RuneCount(buf.Bytes())
	return v.list.Layout(gtx, runes, func(gtx layout.Context, index int) layout.Dimensions {
		data := buf.Bytes()
		for i := 0; i < index; i++ {
			_, size := utf8.DecodeRune(data)
			data = data[size:]
		}
		r, _ := utf8.DecodeRune(data)
		return v.layoutRune(gtx, th, string(r))
	})
}
