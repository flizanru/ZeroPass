package gui

import (
	"image"
	"strings"
	"unicode/utf8"

	"gioui.org/gesture"
	"gioui.org/io/event"
	"gioui.org/io/key"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/awnumar/memguard"
)

const (
	maxPasswordRunes = 256
	maxPasswordBytes = maxPasswordRunes * utf8.UTFMax
)

type securePW struct {
	click    gesture.Click
	buf      *memguard.LockedBuffer
	n        int
	sizes    []int
	focusReq bool
	hint     string
}

func newSecurePW(hint string) *securePW {
	return &securePW{buf: memguard.NewBuffer(maxPasswordBytes), hint: hint}
}

func (sp *securePW) destroy() {
	if sp.buf != nil {
		sp.buf.Destroy()
		sp.buf = nil
	}
	sp.n = 0
	sp.sizes = nil
}

func (sp *securePW) clear() {
	if sp.buf != nil {
		memguard.WipeBytes(sp.buf.Bytes())
	}
	sp.n = 0
	sp.sizes = sp.sizes[:0]
}

func (sp *securePW) runeCount() int { return len(sp.sizes) }

func (sp *securePW) focus() { sp.focusReq = true }

func (sp *securePW) insert(s string) {
	for _, r := range s {
		if r == 0 || r == '\n' || r == '\r' {
			continue
		}
		if len(sp.sizes) >= maxPasswordRunes || sp.n+utf8.UTFMax > len(sp.buf.Bytes()) {
			return
		}
		sz := utf8.EncodeRune(sp.buf.Bytes()[sp.n:], r)
		sp.n += sz
		sp.sizes = append(sp.sizes, sz)
	}
}

func (sp *securePW) backspace() {
	if len(sp.sizes) == 0 {
		return
	}
	sz := sp.sizes[len(sp.sizes)-1]
	sp.sizes = sp.sizes[:len(sp.sizes)-1]
	for i := sp.n - sz; i < sp.n; i++ {
		sp.buf.Bytes()[i] = 0
	}
	sp.n -= sz
}

func (sp *securePW) export() *memguard.LockedBuffer {
	out := memguard.NewBuffer(sp.n)
	copy(out.Bytes(), sp.buf.Bytes()[:sp.n])
	return out
}

func (sp *securePW) setBytes(src []byte) {
	sp.clear()
	for i := 0; i < len(src); {
		r, size := utf8.DecodeRune(src[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			continue
		}
		if len(sp.sizes) >= maxPasswordRunes || sp.n+size > len(sp.buf.Bytes()) {
			break
		}
		copy(sp.buf.Bytes()[sp.n:], src[i:i+size])
		sp.n += size
		sp.sizes = append(sp.sizes, size)
		i += size
	}
	memguard.WipeBytes(src)
}

func (sp *securePW) update(gtx layout.Context) (submit bool) {
	if sp.focusReq {
		gtx.Execute(key.FocusCmd{Tag: sp})
		sp.focusReq = false
	}
	for {
		ev, ok := sp.click.Update(gtx.Source)
		if !ok {
			break
		}
		if ev.Kind == gesture.KindPress {
			gtx.Execute(key.FocusCmd{Tag: sp})
		}
	}
	filters := []event.Filter{
		key.FocusFilter{Target: sp},
		key.Filter{Focus: sp, Name: key.NameDeleteBackward},
		key.Filter{Focus: sp, Name: key.NameReturn},
		key.Filter{Focus: sp, Name: key.NameEnter},
	}
	for {
		ev, ok := gtx.Event(filters...)
		if !ok {
			break
		}
		switch ke := ev.(type) {
		case key.EditEvent:
			sp.insert(ke.Text)
		case key.Event:
			if ke.State != key.Press {
				break
			}
			switch ke.Name {
			case key.NameDeleteBackward:
				sp.backspace()
			case key.NameReturn, key.NameEnter:
				submit = true
			}
		}
	}
	return submit
}

func (sp *securePW) layout(gtx layout.Context, th *material.Theme) layout.Dimensions {
	focused := gtx.Focused(sp)
	borderCol := th.Fg
	borderCol.A = 0x60
	borderWidth := unit.Dp(1)
	if focused {
		borderCol = th.ContrastBg
		borderWidth = unit.Dp(2)
	}

	dims := widget.Border{Color: borderCol, Width: borderWidth, CornerRadius: unit.Dp(4)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				var lbl material.LabelStyle
				if sp.runeCount() == 0 {
					lbl = material.Body1(th, sp.hint)
					lbl.Color = th.Fg
					lbl.Color.A = 0x80
				} else {
					lbl = material.Body1(th, strings.Repeat("•", sp.runeCount()))
				}
				lbl.MaxLines = 1
				return lbl.Layout(gtx)
			})
		})

	defer clip.Rect(image.Rectangle{Max: dims.Size}).Push(gtx.Ops).Pop()
	event.Op(gtx.Ops, sp)
	key.InputHintOp{Tag: sp, Hint: key.HintPassword}.Add(gtx.Ops)
	pointer.CursorText.Add(gtx.Ops)
	sp.click.Add(gtx.Ops)
	return dims
}
