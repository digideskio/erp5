<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="File" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_Cacheable__manager_id</string> </key>
            <value> <string>http_cache</string> </value>
        </item>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts83858910.12</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>de.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

﻿/*\r\n
 * FCKeditor - The text editor for Internet - http://www.fckeditor.net\r\n
 * Copyright (C) 2003-2010 Frederico Caldeira Knabben\r\n
 *\r\n
 * == BEGIN LICENSE ==\r\n
 *\r\n
 * Licensed under the terms of any of the following licenses at your\r\n
 * choice:\r\n
 *\r\n
 *  - GNU General Public License Version 2 or later (the "GPL")\r\n
 *    http://www.gnu.org/licenses/gpl.html\r\n
 *\r\n
 *  - GNU Lesser General Public License Version 2.1 or later (the "LGPL")\r\n
 *    http://www.gnu.org/licenses/lgpl.html\r\n
 *\r\n
 *  - Mozilla Public License Version 1.1 or later (the "MPL")\r\n
 *    http://www.mozilla.org/MPL/MPL-1.1.html\r\n
 *\r\n
 * == END LICENSE ==\r\n
 *\r\n
 * German language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Symbolleiste einklappen",\r\n
ToolbarExpand\t\t: "Symbolleiste ausklappen",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Speichern",\r\n
NewPage\t\t\t\t: "Neue Seite",\r\n
Preview\t\t\t\t: "Vorschau",\r\n
Cut\t\t\t\t\t: "Ausschneiden",\r\n
Copy\t\t\t\t: "Kopieren",\r\n
Paste\t\t\t\t: "Einfügen",\r\n
PasteText\t\t\t: "aus Textdatei einfügen",\r\n
PasteWord\t\t\t: "aus MS-Word einfügen",\r\n
Print\t\t\t\t: "Drucken",\r\n
SelectAll\t\t\t: "Alles auswählen",\r\n
RemoveFormat\t\t: "Formatierungen entfernen",\r\n
InsertLinkLbl\t\t: "Link",\r\n
InsertLink\t\t\t: "Link einfügen/editieren",\r\n
RemoveLink\t\t\t: "Link entfernen",\r\n
VisitLink\t\t\t: "Link aufrufen",\r\n
Anchor\t\t\t\t: "Anker einfügen/editieren",\r\n
AnchorDelete\t\t: "Anker entfernen",\r\n
InsertImageLbl\t\t: "Bild",\r\n
InsertImage\t\t\t: "Bild einfügen/editieren",\r\n
InsertFlashLbl\t\t: "Flash",\r\n
InsertFlash\t\t\t: "Flash einfügen/editieren",\r\n
InsertTableLbl\t\t: "Tabelle",\r\n
InsertTable\t\t\t: "Tabelle einfügen/editieren",\r\n
InsertLineLbl\t\t: "Linie",\r\n
InsertLine\t\t\t: "Horizontale Linie einfügen",\r\n
InsertSpecialCharLbl: "Sonderzeichen",\r\n
InsertSpecialChar\t: "Sonderzeichen einfügen/editieren",\r\n
InsertSmileyLbl\t\t: "Smiley",\r\n
InsertSmiley\t\t: "Smiley einfügen",\r\n
About\t\t\t\t: "Über FCKeditor",\r\n
Bold\t\t\t\t: "Fett",\r\n
Italic\t\t\t\t: "Kursiv",\r\n
Underline\t\t\t: "Unterstrichen",\r\n
StrikeThrough\t\t: "Durchgestrichen",\r\n
Subscript\t\t\t: "Tiefgestellt",\r\n
Superscript\t\t\t: "Hochgestellt",\r\n
LeftJustify\t\t\t: "Linksbündig",\r\n
CenterJustify\t\t: "Zentriert",\r\n
RightJustify\t\t: "Rechtsbündig",\r\n
BlockJustify\t\t: "Blocksatz",\r\n
DecreaseIndent\t\t: "Einzug verringern",\r\n
IncreaseIndent\t\t: "Einzug erhöhen",\r\n
Blockquote\t\t\t: "Zitatblock",\r\n
CreateDiv\t\t\t: "Erzeuge Div Block",\r\n
EditDiv\t\t\t\t: "Bearbeite Div Block",\r\n
DeleteDiv\t\t\t: "Entferne Div Block",\r\n
Undo\t\t\t\t: "Rückgängig",\r\n
Redo\t\t\t\t: "Wiederherstellen",\r\n
NumberedListLbl\t\t: "Nummerierte Liste",\r\n
NumberedList\t\t: "Nummerierte Liste einfügen/entfernen",\r\n
BulletedListLbl\t\t: "Liste",\r\n
BulletedList\t\t: "Liste einfügen/entfernen",\r\n
ShowTableBorders\t: "Zeige Tabellenrahmen",\r\n
ShowDetails\t\t\t: "Zeige Details",\r\n
Style\t\t\t\t: "Stil",\r\n
FontFormat\t\t\t: "Format",\r\n
Font\t\t\t\t: "Schriftart",\r\n
FontSize\t\t\t: "Größe",\r\n
TextColor\t\t\t: "Textfarbe",\r\n
BGColor\t\t\t\t: "Hintergrundfarbe",\r\n
Source\t\t\t\t: "Quellcode",\r\n
Find\t\t\t\t: "Suchen",\r\n
Replace\t\t\t\t: "Ersetzen",\r\n
SpellCheck\t\t\t: "Rechtschreibprüfung",\r\n
UniversalKeyboard\t: "Universal-Tastatur",\r\n
PageBreakLbl\t\t: "Seitenumbruch",\r\n
PageBreak\t\t\t: "Seitenumbruch einfügen",\r\n
\r\n
Form\t\t\t: "Formular",\r\n
Checkbox\t\t: "Checkbox",\r\n
RadioButton\t\t: "Radiobutton",\r\n
TextField\t\t: "Textfeld einzeilig",\r\n
Textarea\t\t: "Textfeld mehrzeilig",\r\n
HiddenField\t\t: "verstecktes Feld",\r\n
Button\t\t\t: "Klickbutton",\r\n
SelectionField\t: "Auswahlfeld",\r\n
ImageButton\t\t: "Bildbutton",\r\n
\r\n
FitWindow\t\t: "Editor maximieren",\r\n
ShowBlocks\t\t: "Blöcke anzeigen",\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Link editieren",\r\n
CellCM\t\t\t\t: "Zelle",\r\n
RowCM\t\t\t\t: "Zeile",\r\n
ColumnCM\t\t\t: "Spalte",\r\n
InsertRowAfter\t\t: "Zeile unterhalb einfügen",\r\n
InsertRowBefore\t\t: "Zeile oberhalb einfügen",\r\n
DeleteRows\t\t\t: "Zeile entfernen",\r\n
InsertColumnAfter\t: "Spalte rechts danach einfügen",\r\n
InsertColumnBefore\t: "Spalte links davor einfügen",\r\n
DeleteColumns\t\t: "Spalte löschen",\r\n
InsertCellAfter\t\t: "Zelle danach einfügen",\r\n
InsertCellBefore\t: "Zelle davor einfügen",\r\n
DeleteCells\t\t\t: "Zelle löschen",\r\n
MergeCells\t\t\t: "Zellen verbinden",\r\n
MergeRight\t\t\t: "nach rechts verbinden",\r\n
MergeDown\t\t\t: "nach unten verbinden",\r\n
HorizontalSplitCell\t: "Zelle horizontal teilen",\r\n
VerticalSplitCell\t: "Zelle vertikal teilen",\r\n
TableDelete\t\t\t: "Tabelle löschen",\r\n
CellProperties\t\t: "Zellen-Eigenschaften",\r\n
TableProperties\t\t: "Tabellen-Eigenschaften",\r\n
ImageProperties\t\t: "Bild-Eigenschaften",\r\n
FlashProperties\t\t: "Flash-Eigenschaften",\r\n
\r\n
AnchorProp\t\t\t: "Anker-Eigenschaften",\r\n
ButtonProp\t\t\t: "Button-Eigenschaften",\r\n
CheckboxProp\t\t: "Checkbox-Eigenschaften",\r\n
HiddenFieldProp\t\t: "Verstecktes Feld-Eigenschaften",\r\n
RadioButtonProp\t\t: "Optionsfeld-Eigenschaften",\r\n
ImageButtonProp\t\t: "Bildbutton-Eigenschaften",\r\n
TextFieldProp\t\t: "Textfeld (einzeilig) Eigenschaften",\r\n
SelectionFieldProp\t: "Auswahlfeld-Eigenschaften",\r\n
TextareaProp\t\t: "Textfeld (mehrzeilig) Eigenschaften",\r\n
FormProp\t\t\t: "Formular-Eigenschaften",\r\n
\r\n
FontFormats\t\t\t: "Normal;Formatiert;Addresse;Überschrift 1;Überschrift 2;Überschrift 3;Überschrift 4;Überschrift 5;Überschrift 6;Normal (DIV)",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "Bearbeite XHTML. Bitte warten...",\r\n
Done\t\t\t\t: "Fertig",\r\n
PasteWordConfirm\t: "Der Text, den Sie einfügen möchten, scheint aus MS-Word kopiert zu sein. Möchten Sie ihn zuvor bereinigen lassen?",\r\n
NotCompatiblePaste\t: "Diese Funktion steht nur im Internet Explorer ab Version 5.5 zur Verfügung. Möchten Sie den Text unbereinigt einfügen?",\r\n
UnknownToolbarItem\t: "Unbekanntes Menüleisten-Objekt \\"%1\\"",\r\n
UnknownCommand\t\t: "Unbekannter Befehl \\"%1\\"",\r\n
NotImplemented\t\t: "Befehl nicht implementiert",\r\n
UnknownToolbarSet\t: "Menüleiste \\"%1\\" existiert nicht",\r\n
NoActiveX\t\t\t: "Die Sicherheitseinstellungen Ihres Browsers beschränken evtl. einige Funktionen des Editors. Aktivieren Sie die Option \\"ActiveX-Steuerelemente und Plugins ausführen\\" in den Sicherheitseinstellungen, um diese Funktionen nutzen zu können",\r\n
BrowseServerBlocked : "Ein Auswahlfenster konnte nicht geöffnet werden. Stellen Sie sicher, das alle Popup-Blocker ausgeschaltet sind.",\r\n
DialogBlocked\t\t: "Das Dialog-Fenster konnte nicht geöffnet werden. Stellen Sie sicher, das alle Popup-Blocker ausgeschaltet sind.",\r\n
VisitLinkBlocked\t: "Es war leider nicht möglich ein neues Fenster zu öffnen. Bitte versichern Sie sich das der Popup-Blocker ausgeschaltet ist.",\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "OK",\r\n
DlgBtnCancel\t\t: "Abbrechen",\r\n
DlgBtnClose\t\t\t: "Schließen",\r\n
DlgBtnBrowseServer\t: "Server durchsuchen",\r\n
DlgAdvancedTag\t\t: "Erweitert",\r\n
DlgOpOther\t\t\t: "<andere>",\r\n
DlgInfoTab\t\t\t: "Info",\r\n
DlgAlertUrl\t\t\t: "Bitte tragen Sie die URL ein",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<nichts>",\r\n
DlgGenId\t\t\t: "ID",\r\n
DlgGenLangDir\t\t: "Schreibrichtung",\r\n
DlgGenLangDirLtr\t: "Links nach Rechts (LTR)",\r\n
DlgGenLangDirRtl\t: "Rechts nach Links (RTL)",\r\n
DlgGenLangCode\t\t: "Sprachenkürzel",\r\n
DlgGenAccessKey\t\t: "Zugriffstaste",\r\n
DlgGenName\t\t\t: "Name",\r\n
DlgGenTabIndex\t\t: "Tab-Index",\r\n
DlgGenLongDescr\t\t: "Langform URL",\r\n
DlgGenClass\t\t\t: "Stylesheet Klasse",\r\n
DlgGenTitle\t\t\t: "Titel Beschreibung",\r\n
DlgGenContType\t\t: "Inhaltstyp",\r\n
DlgGenLinkCharset\t: "Ziel-Zeichensatz",\r\n
DlgGenStyle\t\t\t: "Style",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Bild-Eigenschaften",\r\n
DlgImgInfoTab\t\t: "Bild-Info",\r\n
DlgImgBtnUpload\t\t: "Zum Server senden",\r\n
DlgImgURL\t\t\t: "Bildauswahl",\r\n
DlgImgUpload\t\t: "Upload",\r\n
DlgImgAlt\t\t\t: "Alternativer Text",\r\n
DlgImgWidth\t\t\t: "Breite",\r\n
DlgImgHeight\t\t: "Höhe",\r\n
DlgImgLockRatio\t\t: "Größenverhältniss beibehalten",\r\n
DlgBtnResetSize\t\t: "Größe zurücksetzen",\r\n
DlgImgBorder\t\t: "Rahmen",\r\n
DlgImgHSpace\t\t: "Horizontal-Abstand",\r\n
DlgImgVSpace\t\t: "Vertikal-Abstand",\r\n
DlgImgAlign\t\t\t: "Ausrichtung",\r\n
DlgImgAlignLeft\t\t: "Links",\r\n
DlgImgAlignAbsBottom: "Abs Unten",\r\n
DlgImgAlignAbsMiddle: "Abs Mitte",\r\n
DlgImgAlignBaseline\t: "Baseline",\r\n
DlgImgAlignBottom\t: "Unten",\r\n
DlgImgAlignMiddle\t: "Mitte",\r\n
DlgImgAlignRight\t: "Rechts",\r\n
DlgImgAlignTextTop\t: "Text Oben",\r\n
DlgImgAlignTop\t\t: "Oben",\r\n
DlgImgPreview\t\t: "Vorschau",\r\n
DlgImgAlertUrl\t\t: "Bitte geben Sie die Bild-URL an",\r\n
DlgImgLinkTab\t\t: "Link",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Flash-Eigenschaften",\r\n
DlgFlashChkPlay\t\t: "autom. Abspielen",\r\n
DlgFlashChkLoop\t\t: "Endlosschleife",\r\n
DlgFlashChkMenu\t\t: "Flash-Menü aktivieren",\r\n
DlgFlashScale\t\t: "Skalierung",\r\n
DlgFlashScaleAll\t: "Alles anzeigen",\r\n
DlgFlashScaleNoBorder\t: "ohne Rand",\r\n
DlgFlashScaleFit\t: "Passgenau",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Link",\r\n
DlgLnkInfoTab\t\t: "Link-Info",\r\n
DlgLnkTargetTab\t\t: "Zielseite",\r\n
\r\n
DlgLnkType\t\t\t: "Link-Typ",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Anker in dieser Seite",\r\n
DlgLnkTypeEMail\t\t: "E-Mail",\r\n
DlgLnkProto\t\t\t: "Protokoll",\r\n
DlgLnkProtoOther\t: "<anderes>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Anker auswählen",\r\n
DlgLnkAnchorByName\t: "nach Anker Name",\r\n
DlgLnkAnchorById\t: "nach Element Id",\r\n
DlgLnkNoAnchors\t\t: "(keine Anker im Dokument vorhanden)",\r\n
DlgLnkEMail\t\t\t: "E-Mail Addresse",\r\n
DlgLnkEMailSubject\t: "Betreffzeile",\r\n
DlgLnkEMailBody\t\t: "Nachrichtentext",\r\n
DlgLnkUpload\t\t: "Upload",\r\n
DlgLnkBtnUpload\t\t: "Zum Server senden",\r\n
\r\n
DlgLnkTarget\t\t: "Zielseite",\r\n
DlgLnkTargetFrame\t: "<Frame>",\r\n
DlgLnkTargetPopup\t: "<Pop-up Fenster>",\r\n
DlgLnkTargetBlank\t: "Neues Fenster (_blank)",\r\n
DlgLnkTargetParent\t: "Oberes Fenster (_parent)",\r\n
DlgLnkTargetSelf\t: "Gleiches Fenster (_self)",\r\n
DlgLnkTargetTop\t\t: "Oberstes Fenster (_top)",\r\n
DlgLnkTargetFrameName\t: "Ziel-Fenster-Name",\r\n
DlgLnkPopWinName\t: "Pop-up Fenster-Name",\r\n
DlgLnkPopWinFeat\t: "Pop-up Fenster-Eigenschaften",\r\n
DlgLnkPopResize\t\t: "Vergrößerbar",\r\n
DlgLnkPopLocation\t: "Adress-Leiste",\r\n
DlgLnkPopMenu\t\t: "Menü-Leiste",\r\n
DlgLnkPopScroll\t\t: "Rollbalken",\r\n
DlgLnkPopStatus\t\t: "Statusleiste",\r\n
DlgLnkPopToolbar\t: "Werkzeugleiste",\r\n
DlgLnkPopFullScrn\t: "Vollbild (IE)",\r\n
DlgLnkPopDependent\t: "Abhängig (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Breite",\r\n
DlgLnkPopHeight\t\t: "Höhe",\r\n
DlgLnkPopLeft\t\t: "Linke Position",\r\n
DlgLnkPopTop\t\t: "Obere Position",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Bitte geben Sie die Link-URL an",\r\n
DlnLnkMsgNoEMail\t: "Bitte geben Sie e-Mail Adresse an",\r\n
DlnLnkMsgNoAnchor\t: "Bitte wählen Sie einen Anker aus",\r\n
DlnLnkMsgInvPopName\t: "Der Name des Popups muss mit einem Buchstaben beginnen und darf keine Leerzeichen enthalten",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Farbauswahl",\r\n
DlgColorBtnClear\t: "Keine Farbe",\r\n
DlgColorHighlight\t: "Vorschau",\r\n
DlgColorSelected\t: "Ausgewählt",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Smiley auswählen",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Sonderzeichen auswählen",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Tabellen-Eigenschaften",\r\n
DlgTableRows\t\t: "Zeile",\r\n
DlgTableColumns\t\t: "Spalte",\r\n
DlgTableBorder\t\t: "Rahmen",\r\n
DlgTableAlign\t\t: "Ausrichtung",\r\n
DlgTableAlignNotSet\t: "<keine>",\r\n
DlgTableAlignLeft\t: "Links",\r\n
DlgTableAlignCenter\t: "Zentriert",\r\n
DlgTableAlignRight\t: "Rechts",\r\n
DlgTableWidth\t\t: "Breite",\r\n
DlgTableWidthPx\t\t: "Pixel",\r\n
DlgTableWidthPc\t\t: "%",\r\n
DlgTableHeight\t\t: "Höhe",\r\n
DlgTableCellSpace\t: "Zellenabstand außen",\r\n
DlgTableCellPad\t\t: "Zellenabstand innen",\r\n
DlgTableCaption\t\t: "Überschrift",\r\n
DlgTableSummary\t\t: "Inhaltsübersicht",\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Zellen-Eigenschaften",\r\n
DlgCellWidth\t\t: "Breite",\r\n
DlgCellWidthPx\t\t: "Pixel",\r\n
DlgCellWidthPc\t\t: "%",\r\n
DlgCellHeight\t\t: "Höhe",\r\n
DlgCellWordWrap\t\t: "Umbruch",\r\n
DlgCellWordWrapNotSet\t: "<keiner>",\r\n
DlgCellWordWrapYes\t: "Ja",\r\n
DlgCellWordWrapNo\t: "Nein",\r\n
DlgCellHorAlign\t\t: "Horizontale Ausrichtung",\r\n
DlgCellHorAlignNotSet\t: "<keine>",\r\n
DlgCellHorAlignLeft\t: "Links",\r\n
DlgCellHorAlignCenter\t: "Zentriert",\r\n
DlgCellHorAlignRight: "Rechts",\r\n
DlgCellVerAlign\t\t: "Vertikale Ausrichtung",\r\n
DlgCellVerAlignNotSet\t: "<keine>",\r\n
DlgCellVerAlignTop\t: "Oben",\r\n
DlgCellVerAlignMiddle\t: "Mitte",\r\n
DlgCellVerAlignBottom\t: "Unten",\r\n
DlgCellVerAlignBaseline\t: "Grundlinie",\r\n
DlgCellType\t\t: "Cell Type",\t//MISSING\r\n
DlgCellTypeData\t\t: "Data",\t//MISSING\r\n
DlgCellTypeHeader\t: "Header",\t//MISSING\r\n
DlgCellRowSpan\t\t: "Zeilen zusammenfassen",\r\n
DlgCellCollSpan\t\t: "Spalten zusammenfassen",\r\n
DlgCellBackColor\t: "Hintergrundfarbe",\r\n
DlgCellBorderColor\t: "Rahmenfarbe",\r\n
DlgCellBtnSelect\t: "Auswahl...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Suchen und Ersetzen",\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Finden",\r\n
DlgFindFindBtn\t\t: "Finden",\r\n
DlgFindNotFoundMsg\t: "Der gesuchte Text wurde nicht gefunden.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Ersetzen",\r\n
DlgReplaceFindLbl\t\t: "Suche nach:",\r\n
DlgReplaceReplaceLbl\t: "Ersetze mit:",\r\n
DlgReplaceCaseChk\t\t: "Groß-Kleinschreibung beachten",\r\n
DlgReplaceReplaceBtn\t: "Ersetzen",\r\n
DlgReplaceReplAllBtn\t: "Alle Ersetzen",\r\n
DlgReplaceWordChk\t\t: "Nur ganze Worte suchen",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "Die Sicherheitseinstellungen Ihres Browsers lassen es nicht zu, den Text automatisch auszuschneiden. Bitte benutzen Sie die System-Zwischenablage über STRG-X (ausschneiden) und STRG-V (einfügen).",\r\n
PasteErrorCopy\t: "Die Sicherheitseinstellungen Ihres Browsers lassen es nicht zu, den Text automatisch kopieren. Bitte benutzen Sie die System-Zwischenablage über STRG-C (kopieren).",\r\n
\r\n
PasteAsText\t\t: "Als Text einfügen",\r\n
PasteFromWord\t: "Aus Word einfügen",\r\n
\r\n
DlgPasteMsg2\t: "Bitte fügen Sie den Text in der folgenden Box über die Tastatur (mit <STRONG>Strg+V</STRONG>) ein und bestätigen Sie mit <STRONG>OK</STRONG>.",\r\n
DlgPasteSec\t\t: "Aufgrund von Sicherheitsbeschränkungen Ihres Browsers kann der Editor nicht direkt auf die Zwischenablage zugreifen. Bitte fügen Sie den Inhalt erneut in diesem Fenster ein.",\r\n
DlgPasteIgnoreFont\t\t: "Ignoriere Schriftart-Definitionen",\r\n
DlgPasteRemoveStyles\t: "Entferne Style-Definitionen",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Automatisch",\r\n
ColorMoreColors\t: "Weitere Farben...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Dokument-Eigenschaften",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Anker-Eigenschaften",\r\n
DlgAnchorName\t\t: "Anker Name",\r\n
DlgAnchorErrorName\t: "Bitte geben Sie den Namen des Ankers ein",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Nicht im Wörterbuch",\r\n
DlgSpellChangeTo\t\t: "Ändern in",\r\n
DlgSpellBtnIgnore\t\t: "Ignorieren",\r\n
DlgSpellBtnIgnoreAll\t: "Alle Ignorieren",\r\n
DlgSpellBtnReplace\t\t: "Ersetzen",\r\n
DlgSpellBtnReplaceAll\t: "Alle Ersetzen",\r\n
DlgSpellBtnUndo\t\t\t: "Rückgängig",\r\n
DlgSpellNoSuggestions\t: " - keine Vorschläge - ",\r\n
DlgSpellProgress\t\t: "Rechtschreibprüfung läuft...",\r\n
DlgSpellNoMispell\t\t: "Rechtschreibprüfung abgeschlossen - keine Fehler gefunden",\r\n
DlgSpellNoChanges\t\t: "Rechtschreibprüfung abgeschlossen - keine Worte geändert",\r\n
DlgSpellOneChange\t\t: "Rechtschreibprüfung abgeschlossen - ein Wort geändert",\r\n
DlgSpellManyChanges\t\t: "Rechtschreibprüfung abgeschlossen - %1 Wörter geändert",\r\n
\r\n
IeSpellDownload\t\t\t: "Rechtschreibprüfung nicht installiert. Möchten Sie sie jetzt herunterladen?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Text (Wert)",\r\n
DlgButtonType\t\t: "Typ",\r\n
DlgButtonTypeBtn\t: "Button",\r\n
DlgButtonTypeSbm\t: "Absenden",\r\n
DlgButtonTypeRst\t: "Zurücksetzen",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Name",\r\n
DlgCheckboxValue\t: "Wert",\r\n
DlgCheckboxSelected\t: "ausgewählt",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Name",\r\n
DlgFormAction\t: "Action",\r\n
DlgFormMethod\t: "Method",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Name",\r\n
DlgSelectValue\t\t: "Wert",\r\n
DlgSelectSize\t\t: "Größe",\r\n
DlgSelectLines\t\t: "Linien",\r\n
DlgSelectChkMulti\t: "Erlaube Mehrfachauswahl",\r\n
DlgSelectOpAvail\t: "Mögliche Optionen",\r\n
DlgSelectOpText\t\t: "Text",\r\n
DlgSelectOpValue\t: "Wert",\r\n
DlgSelectBtnAdd\t\t: "Hinzufügen",\r\n
DlgSelectBtnModify\t: "Ändern",\r\n
DlgSelectBtnUp\t\t: "Hoch",\r\n
DlgSelectBtnDown\t: "Runter",\r\n
DlgSelectBtnSetValue : "Setze als Standardwert",\r\n
DlgSelectBtnDelete\t: "Entfernen",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Name",\r\n
DlgTextareaCols\t: "Spalten",\r\n
DlgTextareaRows\t: "Reihen",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Name",\r\n
DlgTextValue\t\t: "Wert",\r\n
DlgTextCharWidth\t: "Zeichenbreite",\r\n
DlgTextMaxChars\t\t: "Max. Zeichen",\r\n
DlgTextType\t\t\t: "Typ",\r\n
DlgTextTypeText\t\t: "Text",\r\n
DlgTextTypePass\t\t: "Passwort",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Name",\r\n
DlgHiddenValue\t: "Wert",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Listen-Eigenschaften",\r\n
NumberedListProp\t: "Nummerierte Listen-Eigenschaften",\r\n
DlgLstStart\t\t\t: "Start",\r\n
DlgLstType\t\t\t: "Typ",\r\n
DlgLstTypeCircle\t: "Ring",\r\n
DlgLstTypeDisc\t\t: "Kreis",\r\n
DlgLstTypeSquare\t: "Quadrat",\r\n
DlgLstTypeNumbers\t: "Nummern (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Kleinbuchstaben (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Großbuchstaben (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Kleine römische Zahlen (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Große römische Zahlen (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Allgemein",\r\n
DlgDocBackTab\t\t: "Hintergrund",\r\n
DlgDocColorsTab\t\t: "Farben und Abstände",\r\n
DlgDocMetaTab\t\t: "Metadaten",\r\n
\r\n
DlgDocPageTitle\t\t: "Seitentitel",\r\n
DlgDocLangDir\t\t: "Schriftrichtung",\r\n
DlgDocLangDirLTR\t: "Links nach Rechts",\r\n
DlgDocLangDirRTL\t: "Rechts nach Links",\r\n
DlgDocLangCode\t\t: "Sprachkürzel",\r\n
DlgDocCharSet\t\t: "Zeichenkodierung",\r\n
DlgDocCharSetCE\t\t: "Zentraleuropäisch",\r\n
DlgDocCharSetCT\t\t: "traditionell Chinesisch (Big5)",\r\n
DlgDocCharSetCR\t\t: "Kyrillisch",\r\n
DlgDocCharSetGR\t\t: "Griechisch",\r\n
DlgDocCharSetJP\t\t: "Japanisch",\r\n
DlgDocCharSetKR\t\t: "Koreanisch",\r\n
DlgDocCharSetTR\t\t: "Türkisch",\r\n
DlgDocCharSetUN\t\t: "Unicode (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "Westeuropäisch",\r\n
DlgDocCharSetOther\t: "Andere Zeichenkodierung",\r\n
\r\n
DlgDocDocType\t\t: "Dokumententyp",\r\n
DlgDocDocTypeOther\t: "Anderer Dokumententyp",\r\n
DlgDocIncXHTML\t\t: "Beziehe XHTML Deklarationen ein",\r\n
DlgDocBgColor\t\t: "Hintergrundfarbe",\r\n
DlgDocBgImage\t\t: "Hintergrundbild URL",\r\n
DlgDocBgNoScroll\t: "feststehender Hintergrund",\r\n
DlgDocCText\t\t\t: "Text",\r\n
DlgDocCLink\t\t\t: "Link",\r\n
DlgDocCVisited\t\t: "Besuchter Link",\r\n
DlgDocCActive\t\t: "Aktiver Link",\r\n
DlgDocMargins\t\t: "Seitenränder",\r\n
DlgDocMaTop\t\t\t: "Oben",\r\n
DlgDocMaLeft\t\t: "Links",\r\n
DlgDocMaRight\t\t: "Rechts",\r\n
DlgDocMaBottom\t\t: "Unten",\r\n
DlgDocMeIndex\t\t: "Schlüsselwörter (durch Komma getrennt)",\r\n
DlgDocMeDescr\t\t: "Dokument-Beschreibung",\r\n
DlgDocMeAuthor\t\t: "Autor",\r\n
DlgDocMeCopy\t\t: "Copyright",\r\n
DlgDocPreview\t\t: "Vorschau",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Vorlagen",\r\n
DlgTemplatesTitle\t: "Vorlagen",\r\n
DlgTemplatesSelMsg\t: "Klicken Sie auf eine Vorlage, um sie im Editor zu öffnen (der aktuelle Inhalt wird dabei gelöscht!):",\r\n
DlgTemplatesLoading\t: "Liste der Vorlagen wird geladen. Bitte warten...",\r\n
DlgTemplatesNoTpl\t: "(keine Vorlagen definiert)",\r\n
DlgTemplatesReplace\t: "Aktuellen Inhalt ersetzen",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Über",\r\n
DlgAboutBrowserInfoTab\t: "Browser-Info",\r\n
DlgAboutLicenseTab\t: "Lizenz",\r\n
DlgAboutVersion\t\t: "Version",\r\n
DlgAboutInfo\t\t: "Für weitere Informationen siehe",\r\n
\r\n
// Div Dialog\r\n
DlgDivGeneralTab\t: "Allgemein",\r\n
DlgDivAdvancedTab\t: "Erweitert",\r\n
DlgDivStyle\t\t: "Style",\r\n
DlgDivInlineStyle\t: "Inline Style",\r\n
\r\n
ScaytTitle\t\t\t: "SCAYT",\t//MISSING\r\n
ScaytTitleOptions\t: "Options",\t//MISSING\r\n
ScaytTitleLangs\t\t: "Languages",\t//MISSING\r\n
ScaytTitleAbout\t\t: "About"\t//MISSING\r\n
};\r\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>19360</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
