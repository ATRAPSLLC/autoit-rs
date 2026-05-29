; AutoHotkey JB01 fixture - benign, deterministic.
#NoTrayIcon
sName := "Sample"
Greet(who) {
   return "Hello, " . who . "!"
}
MsgBox, % Greet(sName)
Return
