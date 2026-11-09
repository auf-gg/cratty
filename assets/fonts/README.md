CrattySymbols-Regular.ttf — Symbols Nerd Font Mono from Nerd Fonts v3.5.1
(https://github.com/ryanoasis/nerd-fonts/releases/tag/v3.5.1, NerdFontsSymbolsOnly)
with two changes:

- the letter "m" is mapped to an empty glyph: gpui won't load a font without "m"
  (it measures width by it), and an icons-only font doesn't contain it;
- the family is renamed to "Cratty Symbols" so the modified copy does not
  pass itself off as the original (some icon sets are OFL 1.1 with
  reserved names).

Embedded in the program as the default terminal icon font — as kitty does.
Nerd Fonts license: MIT, see LICENSE-nerd-fonts; the licenses of individual icon
sets are listed in the Nerd Fonts project README.
