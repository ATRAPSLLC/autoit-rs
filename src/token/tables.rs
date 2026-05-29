//! Static token lookup tables.

/// Keyword names indexed by token id.
pub const KEYWORDS: &[&str] = &[
    "",
    "And",
    "Or",
    "Not",
    "If",
    "Then",
    "Else",
    "ElseIf",
    "EndIf",
    "While",
    "WEnd",
    "Do",
    "Until",
    "For",
    "Next",
    "To",
    "Step",
    "In",
    "ExitLoop",
    "ContinueLoop",
    "Select",
    "Case",
    "EndSelect",
    "Switch",
    "EndSwitch",
    "ContinueCase",
    "Dim",
    "ReDim",
    "Local",
    "Global",
    "Const",
    "Static",
    "Func",
    "EndFunc",
    "Return",
    "Exit",
    "ByRef",
    "With",
    "EndWith",
    "True",
    "False",
    "Default",
    "Null",
    "Volatile",
    "Enum",
];

/// Verified function ids.
pub const FUNCTIONS_BY_ID: &[(i32, &str)] = &[
    (0, "Abs"),
    (1, "ACos"),
    (2, "AdlibRegister"),
    (3, "AdlibUnRegister"),
    (4, "Asc"),
    (5, "AscW"),
    (6, "ASin"),
    (7, "Assign"),
    (8, "ATan"),
    (9, "AutoItSetOption"),
    (10, "AutoItWinGetTitle"),
    (11, "AutoItWinSetTitle"),
    (12, "Beep"),
    (13, "Binary"),
    (14, "BinaryLen"),
    (15, "BinaryMid"),
    (16, "BinaryToString"),
    (17, "BitAND"),
    (18, "BitNOT"),
    (19, "BitOR"),
    (20, "BitRotate"),
    (21, "BitShift"),
    (22, "BitXOR"),
    (23, "BlockInput"),
    (24, "Break"),
    (25, "Call"),
    (26, "CDTray"),
    (27, "Ceiling"),
    (28, "Chr"),
    (29, "ChrW"),
    (30, "ClipGet"),
    (31, "ClipPut"),
    (32, "ConsoleRead"),
    (33, "ConsoleWrite"),
    (34, "ConsoleWriteError"),
    (35, "ControlClick"),
    (36, "ControlCommand"),
    (37, "ControlDisable"),
    (38, "ControlEnable"),
    (39, "ControlFocus"),
    (40, "ControlGetFocus"),
    (41, "ControlGetHandle"),
    (42, "ControlGetPos"),
    (43, "ControlGetText"),
    (44, "ControlHide"),
    (45, "ControlListView"),
    (46, "ControlMove"),
    (47, "ControlSend"),
    (48, "ControlSetText"),
    (49, "ControlShow"),
    (50, "ControlTreeView"),
    (51, "Cos"),
    (52, "Dec"),
    (53, "DirCopy"),
    (54, "DirCreate"),
    (55, "DirGetSize"),
    (56, "DirMove"),
    (57, "DllCall"),
    (58, "DllCallAddress"),
    (59, "DllCallbackFree"),
    (60, "DllCallbackGetPtr"),
    (61, "DllCallbackRegister"),
    (62, "DllClose"),
    (63, "DllOpen"),
    (64, "DllStructCreate"),
    (65, "DllStructGetData"),
    (66, "DllStructGetPtr"),
    (67, "DllStructGetSize"),
    (68, "DllStructSetData"),
    (69, "DriveGetDrive"),
    (70, "DriveGetFileSystem"),
    (71, "DriveGetLabel"),
    (72, "DriveGetSerial"),
    (73, "DriveGetType"),
    (74, "DriveMapAdd"),
    (75, "DriveMapDel"),
    (76, "DriveMapGet"),
    (77, "DriveSetLabel"),
    (78, "DriveSpaceFree"),
    (79, "DriveSpaceTotal"),
    (80, "DriveStatus"),
    (81, "DummySpeedTest"),
    (82, "EnvGet"),
    (83, "EnvSet"),
    (84, "EnvUpdate"),
    (85, "Eval"),
    (86, "Execute"),
    (87, "Exp"),
    (88, "FileChangeDir"),
    (89, "FileClose"),
    (90, "FileCopy"),
    (91, "FileCreateNTFSLink"),
    (92, "FileCreateShortcut"),
    (93, "FileDelete"),
    (94, "FileExists"),
    (95, "FileFindFirstFile"),
    (96, "FileFindNextFile"),
    (97, "FileFlush"),
    (98, "FileGetAttrib"),
    (99, "FileGetEncoding"),
    (100, "FileGetLongName"),
    (101, "FileGetPos"),
    (102, "FileGetShortcut"),
    (103, "FileGetShortName"),
    (104, "FileGetSize"),
    (105, "FileGetTime"),
    (106, "FileGetVersion"),
    (107, "FileInstall"),
    (108, "FileMove"),
    (109, "FileOpen"),
    (110, "FileOpenDialog"),
    (111, "FileRead"),
    (112, "FileReadLine"),
    (113, "FileReadToArray"),
    (114, "FileRecycle"),
    (115, "FileRecycleEmpty"),
    (116, "FileSaveDialog"),
    (117, "FileSelectFolder"),
    (118, "FileSetAttrib"),
    (119, "FileSetEnd"),
    (120, "FileSetPos"),
    (121, "FileSetTime"),
    (122, "FileWrite"),
    (123, "FileWriteLine"),
    (124, "Floor"),
    (125, "FtpSetProxy"),
    (126, "FuncName"),
    (127, "GUICreate"),
    (128, "GUICtrlCreateAvi"),
    (129, "GUICtrlCreateButton"),
    (130, "GUICtrlCreateCheckbox"),
    (131, "GUICtrlCreateCombo"),
    (132, "GUICtrlCreateContextMenu"),
    (133, "GUICtrlCreateDate"),
    (134, "GUICtrlCreateDummy"),
    (135, "GUICtrlCreateEdit"),
    (136, "GUICtrlCreateGraphic"),
    (137, "GUICtrlCreateGroup"),
    (138, "GUICtrlCreateIcon"),
    (139, "GUICtrlCreateInput"),
    (140, "GUICtrlCreateLabel"),
    (141, "GUICtrlCreateList"),
    (142, "GUICtrlCreateListView"),
    (143, "GUICtrlCreateListViewItem"),
    (144, "GUICtrlCreateMenu"),
    (145, "GUICtrlCreateMenuItem"),
    (146, "GUICtrlCreateMonthCal"),
    (147, "GUICtrlCreateObj"),
    (148, "GUICtrlCreatePic"),
    (149, "GUICtrlCreateProgress"),
    (150, "GUICtrlCreateRadio"),
    (151, "GUICtrlCreateSlider"),
    (152, "GUICtrlCreateTab"),
    (153, "GUICtrlCreateTabItem"),
    (154, "GUICtrlCreateTreeView"),
    (155, "GUICtrlCreateTreeViewItem"),
    (156, "GUICtrlCreateUpdown"),
    (157, "GUICtrlDelete"),
    (158, "GUICtrlGetHandle"),
    (159, "GUICtrlGetState"),
    (160, "GUICtrlRead"),
    (161, "GUICtrlRecvMsg"),
    (162, "GUICtrlRegisterListViewSort"),
    (163, "GUICtrlSendMsg"),
    (164, "GUICtrlSendToDummy"),
    (165, "GUICtrlSetBkColor"),
    (166, "GUICtrlSetColor"),
    (167, "GUICtrlSetCursor"),
    (168, "GUICtrlSetData"),
    (169, "GUICtrlSetDefBkColor"),
    (170, "GUICtrlSetDefColor"),
    (171, "GUICtrlSetFont"),
    (172, "GUICtrlSetGraphic"),
    (173, "GUICtrlSetImage"),
    (174, "GUICtrlSetLimit"),
    (175, "GUICtrlSetOnEvent"),
    (176, "GUICtrlSetPos"),
    (177, "GUICtrlSetResizing"),
    (178, "GUICtrlSetState"),
    (179, "GUICtrlSetStyle"),
    (180, "GUICtrlSetTip"),
    (181, "GUIDelete"),
    (182, "GUIGetCursorInfo"),
    (183, "GUIGetMsg"),
    (184, "GUIGetStyle"),
    (185, "GUIRegisterMsg"),
    (186, "GUISetAccelerators"),
    (187, "GUISetBkColor"),
    (188, "GUISetCoord"),
    (189, "GUISetCursor"),
    (190, "GUISetFont"),
    (191, "GUISetHelp"),
    (192, "GUISetIcon"),
    (193, "GUISetOnEvent"),
    (194, "GUISetState"),
    (195, "GUISetStyle"),
    (196, "GUIStartGroup"),
    (197, "GUISwitch"),
    (198, "Hex"),
    (199, "HotKeySet"),
    (200, "HttpSetProxy"),
    (201, "HttpSetUserAgent"),
    (202, "HWnd"),
    (203, "InetClose"),
    (204, "InetGet"),
    (205, "InetGetInfo"),
    (206, "InetGetSize"),
    (207, "InetRead"),
    (208, "IniDelete"),
    (209, "IniRead"),
    (210, "IniReadSection"),
    (211, "IniReadSectionNames"),
    (212, "IniRenameSection"),
    (213, "IniWrite"),
    (214, "IniWriteSection"),
    (215, "InputBox"),
    (216, "Int"),
    (217, "IsAdmin"),
    (218, "IsArray"),
    (219, "IsBinary"),
    (220, "IsBool"),
    (221, "IsDeclared"),
    (222, "IsDllStruct"),
    (223, "IsFloat"),
    (224, "IsFunc"),
    (225, "IsHWnd"),
    (226, "IsInt"),
    (227, "IsKeyword"),
    (228, "IsMap"),
    (229, "IsNumber"),
    (230, "IsObj"),
    (231, "IsPtr"),
    (232, "IsString"),
    (233, "Log"),
    (234, "MapAppend"),
    (235, "MapExists"),
    (236, "MapKeys"),
    (237, "MapRemove"),
    (238, "MemGetStats"),
    (239, "Mod"),
    (240, "MouseClick"),
    (241, "MouseClickDrag"),
    (242, "MouseDown"),
    (243, "MouseGetCursor"),
    (244, "MouseGetPos"),
    (245, "MouseMove"),
    (246, "MouseUp"),
    (247, "MouseWheel"),
    (248, "MsgBox"),
    (249, "Number"),
    (250, "ObjCreate"),
    (251, "ObjCreateInterface"),
    (252, "ObjEvent"),
    (253, "ObjGet"),
    (254, "ObjName"),
    (255, "OnAutoItExitRegister"),
    (256, "OnAutoItExitUnRegister"),
    (257, "Opt"),
    (258, "Ping"),
    (259, "PixelChecksum"),
    (260, "PixelGetColor"),
    (261, "PixelSearch"),
    (262, "ProcessClose"),
    (263, "ProcessExists"),
    (264, "ProcessGetStats"),
    (265, "ProcessList"),
    (266, "ProcessSetPriority"),
    (267, "ProcessWait"),
    (268, "ProcessWaitClose"),
    (269, "ProgressOff"),
    (270, "ProgressOn"),
    (271, "ProgressSet"),
    (272, "Ptr"),
    (273, "Random"),
    (274, "RegDelete"),
    (275, "RegEnumKey"),
    (276, "RegEnumVal"),
    (277, "RegRead"),
    (278, "RegWrite"),
    (279, "Round"),
    (280, "Run"),
    (281, "RunAs"),
    (282, "RunAsWait"),
    (283, "RunWait"),
    (284, "Send"),
    (285, "SendKeepActive"),
    (286, "SetError"),
    (287, "SetExtended"),
    (288, "ShellExecute"),
    (289, "ShellExecuteWait"),
    (290, "Shutdown"),
    (291, "Sin"),
    (292, "Sleep"),
    (293, "SoundPlay"),
    (294, "SoundSetWaveVolume"),
    (295, "SplashImageOn"),
    (296, "SplashOff"),
    (297, "SplashTextOn"),
    (298, "Sqrt"),
    (299, "SRandom"),
    (300, "StatusbarGetText"),
    (301, "StdErrRead"),
    (302, "StdInWrite"),
    (303, "StdioClose"),
    (304, "StdOutRead"),
    (305, "String"),
    (306, "StringAddCR"),
    (307, "StringCompare"),
    (308, "StringFormat"),
    (309, "StringFromASCIIArray"),
    (310, "StringInStr"),
    (311, "StringIsAlNum"),
    (312, "StringIsAlpha"),
    (313, "StringIsASCII"),
    (314, "StringIsDigit"),
    (315, "StringIsFloat"),
    (316, "StringIsInt"),
    (317, "StringIsLower"),
    (318, "StringIsSpace"),
    (319, "StringIsUpper"),
    (320, "StringIsXDigit"),
    (321, "StringLeft"),
    (322, "StringLen"),
    (323, "StringLower"),
    (324, "StringMid"),
    (325, "StringRegExp"),
    (326, "StringRegExpReplace"),
    (327, "StringReplace"),
    (328, "StringReverse"),
    (329, "StringRight"),
    (330, "StringSplit"),
    (331, "StringStripCR"),
    (332, "StringStripWS"),
    (333, "StringToASCIIArray"),
    (334, "StringToBinary"),
    (335, "StringTrimLeft"),
    (336, "StringTrimRight"),
    (337, "StringUpper"),
    (338, "Tan"),
    (339, "TCPAccept"),
    (340, "TCPCloseSocket"),
    (341, "TCPConnect"),
    (342, "TCPListen"),
    (343, "TCPNameToIP"),
    (344, "TCPRecv"),
    (345, "TCPSend"),
    (346, "TCPShutdown"),
    (347, "TCPStartup"),
    (348, "TimerDiff"),
    (349, "TimerInit"),
    (350, "ToolTip"),
    (351, "TrayCreateItem"),
    (352, "TrayCreateMenu"),
    (353, "TrayGetMsg"),
    (354, "TrayItemDelete"),
    (355, "TrayItemGetHandle"),
    (356, "TrayItemGetState"),
    (357, "TrayItemGetText"),
    (358, "TrayItemSetOnEvent"),
    (359, "TrayItemSetState"),
    (360, "TrayItemSetText"),
    (361, "TraySetClick"),
    (362, "TraySetIcon"),
    (363, "TraySetOnEvent"),
    (364, "TraySetPauseIcon"),
    (365, "TraySetState"),
    (366, "TraySetToolTip"),
    (367, "TrayTip"),
    (368, "UBound"),
    (369, "UDPBind"),
    (370, "UDPCloseSocket"),
    (371, "UDPOpen"),
    (372, "UDPRecv"),
    (373, "UDPSend"),
    (374, "UDPShutdown"),
    (375, "UDPStartup"),
    (376, "VarGetType"),
    (377, "WinActivate"),
    (378, "WinActive"),
    (379, "WinClose"),
    (380, "WinExists"),
    (381, "WinFlash"),
    (382, "WinGetCaretPos"),
    (383, "WinGetClassList"),
    (384, "WinGetClientSize"),
    (385, "WinGetHandle"),
    (386, "WinGetPos"),
    (387, "WinGetProcess"),
    (388, "WinGetState"),
    (389, "WinGetText"),
    (390, "WinGetTitle"),
    (391, "WinKill"),
    (392, "WinList"),
    (393, "WinMenuSelectItem"),
    (394, "WinMinimizeAll"),
    (395, "WinMinimizeAllUndo"),
    (396, "WinMove"),
    (397, "WinSetOnTop"),
    (398, "WinSetState"),
    (399, "WinSetTitle"),
    (400, "WinSetTrans"),
    (401, "WinWait"),
    (402, "WinWaitActive"),
    (403, "WinWaitClose"),
    (404, "WinWaitNotActive"),
];

/// Macro names used for canonicalizing string-form macro tokens.
pub const MACROS: &[&str] = &[
    "AppDataCommonDir",
    "AppDataDir",
    "AutoItExe",
    "AutoItPID",
    "AutoItVersion",
    "AutoItX64",
    "COM_EventObj",
    "CommonFilesDir",
    "Compiled",
    "ComputerName",
    "ComSpec",
    "CPUArch",
    "CR",
    "CRLF",
    "DesktopCommonDir",
    "DesktopDepth",
    "DesktopDir",
    "DesktopHeight",
    "DesktopRefresh",
    "DesktopWidth",
    "DocumentsCommonDir",
    "error",
    "exitCode",
    "exitMethod",
    "extended",
    "FavoritesCommonDir",
    "FavoritesDir",
    "GUI_CtrlHandle",
    "GUI_CtrlId",
    "GUI_DragFile",
    "GUI_DragId",
    "GUI_DropId",
    "GUI_WinHandle",
    "HomeDrive",
    "HomePath",
    "HomeShare",
    "HotKeyPressed",
    "HOUR",
    "IPAddress1",
    "IPAddress2",
    "IPAddress3",
    "IPAddress4",
    "KBLayout",
    "LF",
    "LocalAppDataDir",
    "LogonDNSDomain",
    "LogonDomain",
    "LogonServer",
    "MDAY",
    "MIN",
    "MON",
    "MSEC",
    "MUILang",
    "MyDocumentsDir",
    "NumParams",
    "OSArch",
    "OSBuild",
    "OSLang",
    "OSServicePack",
    "OSType",
    "OSVersion",
    "ProgramFilesDir",
    "ProgramsCommonDir",
    "ProgramsDir",
    "ScriptDir",
    "ScriptFullPath",
    "ScriptLineNumber",
    "ScriptName",
    "SEC",
    "StartMenuCommonDir",
    "StartMenuDir",
    "StartupCommonDir",
    "StartupDir",
    "SW_DISABLE",
    "SW_ENABLE",
    "SW_HIDE",
    "SW_LOCK",
    "SW_MAXIMIZE",
    "SW_MINIMIZE",
    "SW_RESTORE",
    "SW_SHOW",
    "SW_SHOWDEFAULT",
    "SW_SHOWMAXIMIZED",
    "SW_SHOWMINIMIZED",
    "SW_SHOWMINNOACTIVE",
    "SW_SHOWNA",
    "SW_SHOWNOACTIVATE",
    "SW_SHOWNORMAL",
    "SW_UNLOCK",
    "SystemDir",
    "TAB",
    "TempDir",
    "TRAY_ID",
    "TrayIconFlashing",
    "TrayIconVisible",
    "UserName",
    "UserProfileDir",
    "WDAY",
    "WindowsDir",
    "WorkingDir",
    "YDAY",
    "YEAR",
];

/// Returns the keyword name for a numeric id.
///
/// The id is used directly as an index into [`KEYWORDS`], so a negative or
/// out-of-range id yields no result.
///
/// # Arguments
///
/// * `id` - The keyword token id to resolve.
///
/// # Returns
///
/// `Some` with the keyword name, or `None` if `id` is negative or has no entry.
pub fn keyword_by_id(id: i32) -> Option<String> {
    let index = usize::try_from(id).ok()?;
    KEYWORDS.get(index).map(|value| (*value).to_string())
}

/// Returns the function name for a numeric id.
///
/// [`FUNCTIONS_BY_ID`] is kept sorted by ascending id (enforced by the
/// `function_table_matches_checked_data` test), so this resolves with a binary
/// search on the id rather than a linear scan.
///
/// # Arguments
///
/// * `id` - The function token id to resolve.
///
/// # Returns
///
/// `Some` with the function name, or `None` if no entry has that id.
pub fn function_by_id(id: i32) -> Option<String> {
    FUNCTIONS_BY_ID
        .binary_search_by_key(&id, |(candidate, _name)| *candidate)
        .ok()
        .and_then(|index| FUNCTIONS_BY_ID.get(index))
        .map(|(_id, name)| (*name).to_string())
}

/// Returns canonical keyword casing for a string-form token.
///
/// Looks `value` up case-insensitively in [`KEYWORDS`] and returns the table's
/// canonical spelling; if no match is found, the input is returned unchanged.
///
/// # Arguments
///
/// * `value` - The string-form keyword token to canonicalize.
///
/// # Returns
///
/// The canonical keyword spelling, or `value` itself when not a known keyword.
pub fn canonical_keyword(value: &str) -> String {
    canonical_from_slice(KEYWORDS, value).unwrap_or_else(|| value.to_string())
}

/// Returns canonical function casing for a string-form token.
///
/// Scans [`FUNCTIONS_BY_ID`] for a case-insensitive name match and returns the
/// table's canonical spelling; if none matches, the input is returned
/// unchanged.
///
/// # Arguments
///
/// * `value` - The string-form function token to canonicalize.
///
/// # Returns
///
/// The canonical function spelling, or `value` itself when not a known
/// function.
pub fn canonical_function(value: &str) -> String {
    FUNCTIONS_BY_ID
        .iter()
        .find(|(_id, candidate)| candidate.eq_ignore_ascii_case(value))
        .map(|(_id, candidate)| (*candidate).to_string())
        .unwrap_or_else(|| value.to_string())
}

/// Returns canonical macro casing for a string-form token.
///
/// Looks `value` up case-insensitively in [`MACROS`] and returns the table's
/// canonical spelling; if no match is found, the input is returned unchanged.
///
/// # Arguments
///
/// * `value` - The string-form macro token (without the leading `@`).
///
/// # Returns
///
/// The canonical macro spelling, or `value` itself when not a known macro.
pub fn canonical_macro(value: &str) -> String {
    canonical_from_slice(MACROS, value).unwrap_or_else(|| value.to_string())
}

/// Finds the canonical spelling of `value` within a table of names.
///
/// Compares `value` case-insensitively against each entry in `values` and
/// returns the first match's canonical casing.
///
/// # Arguments
///
/// * `values` - The table of canonical names to search.
/// * `value` - The token to match case-insensitively.
///
/// # Returns
///
/// `Some` with the matching canonical name, or `None` if no entry matches.
fn canonical_from_slice(values: &[&str], value: &str) -> Option<String> {
    values
        .iter()
        .find(|candidate| candidate.eq_ignore_ascii_case(value))
        .map(|candidate| (*candidate).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYWORDS_TSV: &str = include_str!("../../data/token/keywords.tsv");
    const FUNCTIONS_TSV: &str = include_str!("../../data/token/functions.tsv");
    const MACROS_TSV: &str = include_str!("../../data/token/macros.tsv");

    #[test]
    fn keyword_table_matches_checked_data() -> Result<(), String> {
        let rows = parse_indexed_rows(KEYWORDS_TSV)?;

        check_eq(rows.len(), KEYWORDS.len(), "keyword row count")?;
        for (id, name) in rows {
            let actual = KEYWORDS
                .get(id)
                .ok_or_else(|| format!("missing keyword id {id}"))?;
            check_eq(*actual, name.as_str(), "keyword")?;
        }
        Ok(())
    }

    #[test]
    fn function_table_matches_checked_data() -> Result<(), String> {
        let rows = parse_i32_rows(FUNCTIONS_TSV)?;

        check_eq(rows.len(), FUNCTIONS_BY_ID.len(), "function row count")?;
        let mut previous_id: Option<i32> = None;
        for (index, (id, name)) in rows.iter().enumerate() {
            let actual = FUNCTIONS_BY_ID
                .get(index)
                .ok_or_else(|| format!("missing function row {index}"))?;
            check_eq(actual.0, *id, "function id")?;
            check_eq(actual.1, name.as_str(), "function name")?;
            // `function_by_id` binary-searches this table, so ids must ascend.
            if previous_id.is_some_and(|previous| previous >= *id) {
                return Err(format!(
                    "function ids not strictly ascending at row {index}"
                ));
            }
            previous_id = Some(*id);
        }
        Ok(())
    }

    #[test]
    fn macro_table_matches_checked_data() -> Result<(), String> {
        let rows = parse_name_rows(MACROS_TSV)?;

        check_eq(rows.len(), MACROS.len(), "macro row count")?;
        for (index, name) in rows.iter().enumerate() {
            let actual = MACROS
                .get(index)
                .ok_or_else(|| format!("missing macro row {index}"))?;
            check_eq(*actual, name.as_str(), "macro name")?;
        }
        Ok(())
    }

    fn parse_indexed_rows(data: &str) -> Result<Vec<(usize, String)>, String> {
        let mut rows = Vec::new();
        for (index, line) in data.lines().enumerate() {
            if should_skip(line) {
                continue;
            }
            let line_number = display_line_number(index)?;
            let (id, name) = line
                .split_once('\t')
                .ok_or_else(|| format!("line {line_number}: missing tab separator"))?;
            rows.push((
                id.parse::<usize>()
                    .map_err(|err| format!("line {line_number}: {err}"))?,
                name.to_string(),
            ));
        }
        Ok(rows)
    }

    fn parse_i32_rows(data: &str) -> Result<Vec<(i32, String)>, String> {
        let mut rows = Vec::new();
        for (index, line) in data.lines().enumerate() {
            if should_skip(line) {
                continue;
            }
            let line_number = display_line_number(index)?;
            let (id, name) = line
                .split_once('\t')
                .ok_or_else(|| format!("line {line_number}: missing tab separator"))?;
            rows.push((
                id.parse::<i32>()
                    .map_err(|err| format!("line {line_number}: {err}"))?,
                name.to_string(),
            ));
        }
        Ok(rows)
    }

    fn parse_name_rows(data: &str) -> Result<Vec<String>, String> {
        let mut rows = Vec::new();
        for line in data.lines() {
            if should_skip(line) {
                continue;
            }
            rows.push(line.to_string());
        }
        Ok(rows)
    }

    fn should_skip(line: &str) -> bool {
        line.is_empty() || line.starts_with('#')
    }

    fn display_line_number(index: usize) -> Result<usize, String> {
        index
            .checked_add(1)
            .ok_or_else(|| "line number overflow".to_string())
    }

    fn check_eq<T>(actual: T, expected: T, context: &str) -> Result<(), String>
    where
        T: core::fmt::Debug + PartialEq,
    {
        if actual == expected {
            Ok(())
        } else {
            Err(format!("{context}: got {actual:?}, expected {expected:?}"))
        }
    }
}
