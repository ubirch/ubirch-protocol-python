serial.onDataReceived(serial.delimiters(Delimiters.Hash), function () {
    r = serial.readUntil(serial.delimiters(Delimiters.Colon))
    g = serial.readUntil(serial.delimiters(Delimiters.Colon))
    b = serial.readUntil(serial.delimiters(Delimiters.Hash))
    basic.setLedColor(basic.rgbw(
    parseInt(r),
    parseInt(g),
    parseInt(b),
    0
    ))
    music.playTone(494, 5)
})
let b = ""
let g = ""
let r = ""
serial.writeLine("Format: R:G:B#")
basic.showLeds(`
    . # # # .
    . . . # .
    . . # # .
    . . . . .
    . . # . .
    `)
basic.forever(function () {
	
})