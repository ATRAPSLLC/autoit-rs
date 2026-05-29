; AutoIt extraction fixture - benign, deterministic source.
#NoTrayIcon
Global $g_sName = "Sample"
Global $g_iCount = 3

Func Greet($sWho)
    Local $sMsg = "Hello, " & $sWho & "!"
    If $sWho = "" Then Return "Hello, world!"
    Return $sMsg
EndFunc

For $i = 1 To $g_iCount
    ConsoleWrite(Greet($g_sName) & @CRLF)
Next

If @Compiled Then FileInstall("payload.txt", @TempDir & "\au3_fixture_payload.txt", 1)

Local $aData[2] = ["alpha", "beta"]
While UBound($aData) > 0
    ConsoleWrite($aData[0] & " says ""hi""" & @CRLF)
    ExitLoop
WEnd
