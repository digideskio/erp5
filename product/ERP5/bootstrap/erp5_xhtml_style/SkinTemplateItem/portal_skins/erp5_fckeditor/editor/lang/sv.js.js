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
            <value> <string>ts83858910.15</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>sv.js</string> </value>
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
 * Swedish language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Dölj verktygsfält",\r\n
ToolbarExpand\t\t: "Visa verktygsfält",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Spara",\r\n
NewPage\t\t\t\t: "Ny sida",\r\n
Preview\t\t\t\t: "Förhandsgranska",\r\n
Cut\t\t\t\t\t: "Klipp ut",\r\n
Copy\t\t\t\t: "Kopiera",\r\n
Paste\t\t\t\t: "Klistra in",\r\n
PasteText\t\t\t: "Klistra in som text",\r\n
PasteWord\t\t\t: "Klistra in från Word",\r\n
Print\t\t\t\t: "Skriv ut",\r\n
SelectAll\t\t\t: "Markera allt",\r\n
RemoveFormat\t\t: "Radera formatering",\r\n
InsertLinkLbl\t\t: "Länk",\r\n
InsertLink\t\t\t: "Infoga/Redigera länk",\r\n
RemoveLink\t\t\t: "Radera länk",\r\n
VisitLink\t\t\t: "Öppna länk",\r\n
Anchor\t\t\t\t: "Infoga/Redigera ankarlänk",\r\n
AnchorDelete\t\t: "Radera ankarlänk",\r\n
InsertImageLbl\t\t: "Bild",\r\n
InsertImage\t\t\t: "Infoga/Redigera bild",\r\n
InsertFlashLbl\t\t: "Flash",\r\n
InsertFlash\t\t\t: "Infoga/Redigera Flash",\r\n
InsertTableLbl\t\t: "Tabell",\r\n
InsertTable\t\t\t: "Infoga/Redigera tabell",\r\n
InsertLineLbl\t\t: "Linje",\r\n
InsertLine\t\t\t: "Infoga horisontal linje",\r\n
InsertSpecialCharLbl: "Utökade tecken",\r\n
InsertSpecialChar\t: "Klistra in utökat tecken",\r\n
InsertSmileyLbl\t\t: "Smiley",\r\n
InsertSmiley\t\t: "Infoga Smiley",\r\n
About\t\t\t\t: "Om FCKeditor",\r\n
Bold\t\t\t\t: "Fet",\r\n
Italic\t\t\t\t: "Kursiv",\r\n
Underline\t\t\t: "Understruken",\r\n
StrikeThrough\t\t: "Genomstruken",\r\n
Subscript\t\t\t: "Nedsänkta tecken",\r\n
Superscript\t\t\t: "Upphöjda tecken",\r\n
LeftJustify\t\t\t: "Vänsterjustera",\r\n
CenterJustify\t\t: "Centrera",\r\n
RightJustify\t\t: "Högerjustera",\r\n
BlockJustify\t\t: "Justera till marginaler",\r\n
DecreaseIndent\t\t: "Minska indrag",\r\n
IncreaseIndent\t\t: "Öka indrag",\r\n
Blockquote\t\t\t: "Blockquote",\t//MISSING\r\n
CreateDiv\t\t\t: "Skapa Div behållare",\r\n
EditDiv\t\t\t\t: "Redigera Div behållare",\r\n
DeleteDiv\t\t\t: "Radera Div behållare",\r\n
Undo\t\t\t\t: "Ångra",\r\n
Redo\t\t\t\t: "Gör om",\r\n
NumberedListLbl\t\t: "Numrerad lista",\r\n
NumberedList\t\t: "Infoga/Radera numrerad lista",\r\n
BulletedListLbl\t\t: "Punktlista",\r\n
BulletedList\t\t: "Infoga/Radera punktlista",\r\n
ShowTableBorders\t: "Visa tabellkant",\r\n
ShowDetails\t\t\t: "Visa radbrytningar",\r\n
Style\t\t\t\t: "Anpassad stil",\r\n
FontFormat\t\t\t: "Teckenformat",\r\n
Font\t\t\t\t: "Typsnitt",\r\n
FontSize\t\t\t: "Storlek",\r\n
TextColor\t\t\t: "Textfärg",\r\n
BGColor\t\t\t\t: "Bakgrundsfärg",\r\n
Source\t\t\t\t: "Källa",\r\n
Find\t\t\t\t: "Sök",\r\n
Replace\t\t\t\t: "Ersätt",\r\n
SpellCheck\t\t\t: "Stavningskontroll",\r\n
UniversalKeyboard\t: "Universellt tangentbord",\r\n
PageBreakLbl\t\t: "Sidbrytning",\r\n
PageBreak\t\t\t: "Infoga sidbrytning",\r\n
\r\n
Form\t\t\t: "Formulär",\r\n
Checkbox\t\t: "Kryssruta",\r\n
RadioButton\t\t: "Alternativknapp",\r\n
TextField\t\t: "Textfält",\r\n
Textarea\t\t: "Textruta",\r\n
HiddenField\t\t: "Dolt fält",\r\n
Button\t\t\t: "Knapp",\r\n
SelectionField\t: "Flervalslista",\r\n
ImageButton\t\t: "Bildknapp",\r\n
\r\n
FitWindow\t\t: "Anpassa till fönstrets storlek",\r\n
ShowBlocks\t\t: "Visa block",\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Redigera länk",\r\n
CellCM\t\t\t\t: "Cell",\r\n
RowCM\t\t\t\t: "Rad",\r\n
ColumnCM\t\t\t: "Kolumn",\r\n
InsertRowAfter\t\t: "Lägg till Rad Efter",\r\n
InsertRowBefore\t\t: "Lägg till Rad Före",\r\n
DeleteRows\t\t\t: "Radera rad",\r\n
InsertColumnAfter\t: "Lägg till Kolumn Efter",\r\n
InsertColumnBefore\t: "Lägg till Kolumn Före",\r\n
DeleteColumns\t\t: "Radera kolumn",\r\n
InsertCellAfter\t\t: "Lägg till Cell Efter",\r\n
InsertCellBefore\t: "Lägg till Cell Före",\r\n
DeleteCells\t\t\t: "Radera celler",\r\n
MergeCells\t\t\t: "Sammanfoga celler",\r\n
MergeRight\t\t\t: "Sammanfoga Höger",\r\n
MergeDown\t\t\t: "Sammanfoga Ner",\r\n
HorizontalSplitCell\t: "Dela Cell Horisontellt",\r\n
VerticalSplitCell\t: "Dela Cell Vertikalt",\r\n
TableDelete\t\t\t: "Radera tabell",\r\n
CellProperties\t\t: "Cellegenskaper",\r\n
TableProperties\t\t: "Tabellegenskaper",\r\n
ImageProperties\t\t: "Bildegenskaper",\r\n
FlashProperties\t\t: "Flashegenskaper",\r\n
\r\n
AnchorProp\t\t\t: "Egenskaper för ankarlänk",\r\n
ButtonProp\t\t\t: "Egenskaper för knapp",\r\n
CheckboxProp\t\t: "Egenskaper för kryssruta",\r\n
HiddenFieldProp\t\t: "Egenskaper för dolt fält",\r\n
RadioButtonProp\t\t: "Egenskaper för alternativknapp",\r\n
ImageButtonProp\t\t: "Egenskaper för bildknapp",\r\n
TextFieldProp\t\t: "Egenskaper för textfält",\r\n
SelectionFieldProp\t: "Egenskaper för flervalslista",\r\n
TextareaProp\t\t: "Egenskaper för textruta",\r\n
FormProp\t\t\t: "Egenskaper för formulär",\r\n
\r\n
FontFormats\t\t\t: "Normal;Formaterad;Adress;Rubrik 1;Rubrik 2;Rubrik 3;Rubrik 4;Rubrik 5;Rubrik 6;Normal (DIV)",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "Bearbetar XHTML. Var god vänta...",\r\n
Done\t\t\t\t: "Klar",\r\n
PasteWordConfirm\t: "Texten du vill klistra in verkar vara kopierad från Word. Vill du rensa innan du klistar in?",\r\n
NotCompatiblePaste\t: "Denna åtgärd är inte tillgängligt för Internet Explorer version 5.5 eller högre. Vill du klistra in utan att rensa?",\r\n
UnknownToolbarItem\t: "Okänt verktygsfält \\"%1\\"",\r\n
UnknownCommand\t\t: "Okänt kommando \\"%1\\"",\r\n
NotImplemented\t\t: "Kommandot finns ej",\r\n
UnknownToolbarSet\t: "Verktygsfält \\"%1\\" finns ej",\r\n
NoActiveX\t\t\t: "Din webläsares säkerhetsinställningar kan begränsa funktionaliteten. Du bör aktivera \\"Kör ActiveX kontroller och plug-ins\\". Fel och avsaknad av funktioner kan annars uppstå.",\r\n
BrowseServerBlocked : "Kunde Ej öppna resursfönstret. Var god och avaktivera alla popup-blockerare.",\r\n
DialogBlocked\t\t: "Kunde Ej öppna dialogfönstret. Var god och avaktivera alla popup-blockerare.",\r\n
VisitLinkBlocked\t: "Kunde Ej öppna nytt fönster. Var god och avaktivera alla popup-blockerare.",\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "OK",\r\n
DlgBtnCancel\t\t: "Avbryt",\r\n
DlgBtnClose\t\t\t: "Stäng",\r\n
DlgBtnBrowseServer\t: "Bläddra på server",\r\n
DlgAdvancedTag\t\t: "Avancerad",\r\n
DlgOpOther\t\t\t: "Övrigt",\r\n
DlgInfoTab\t\t\t: "Information",\r\n
DlgAlertUrl\t\t\t: "Var god och ange en URL",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<ej angivet>",\r\n
DlgGenId\t\t\t: "Id",\r\n
DlgGenLangDir\t\t: "Språkriktning",\r\n
DlgGenLangDirLtr\t: "Vänster till Höger (VTH)",\r\n
DlgGenLangDirRtl\t: "Höger till Vänster (HTV)",\r\n
DlgGenLangCode\t\t: "Språkkod",\r\n
DlgGenAccessKey\t\t: "Behörighetsnyckel",\r\n
DlgGenName\t\t\t: "Namn",\r\n
DlgGenTabIndex\t\t: "Tabindex",\r\n
DlgGenLongDescr\t\t: "URL-beskrivning",\r\n
DlgGenClass\t\t\t: "Stylesheet class",\r\n
DlgGenTitle\t\t\t: "Titel",\r\n
DlgGenContType\t\t: "Innehållstyp",\r\n
DlgGenLinkCharset\t: "Teckenuppställning",\r\n
DlgGenStyle\t\t\t: "Stil",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Bildegenskaper",\r\n
DlgImgInfoTab\t\t: "Bildinformation",\r\n
DlgImgBtnUpload\t\t: "Skicka till server",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "Ladda upp",\r\n
DlgImgAlt\t\t\t: "Alternativ text",\r\n
DlgImgWidth\t\t\t: "Bredd",\r\n
DlgImgHeight\t\t: "Höjd",\r\n
DlgImgLockRatio\t\t: "Lås höjd/bredd förhållanden",\r\n
DlgBtnResetSize\t\t: "Återställ storlek",\r\n
DlgImgBorder\t\t: "Kant",\r\n
DlgImgHSpace\t\t: "Horis. marginal",\r\n
DlgImgVSpace\t\t: "Vert. marginal",\r\n
DlgImgAlign\t\t\t: "Justering",\r\n
DlgImgAlignLeft\t\t: "Vänster",\r\n
DlgImgAlignAbsBottom: "Absolut nederkant",\r\n
DlgImgAlignAbsMiddle: "Absolut centrering",\r\n
DlgImgAlignBaseline\t: "Baslinje",\r\n
DlgImgAlignBottom\t: "Nederkant",\r\n
DlgImgAlignMiddle\t: "Mitten",\r\n
DlgImgAlignRight\t: "Höger",\r\n
DlgImgAlignTextTop\t: "Text överkant",\r\n
DlgImgAlignTop\t\t: "Överkant",\r\n
DlgImgPreview\t\t: "Förhandsgranska",\r\n
DlgImgAlertUrl\t\t: "Var god och ange bildens URL",\r\n
DlgImgLinkTab\t\t: "Länk",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Flashegenskaper",\r\n
DlgFlashChkPlay\t\t: "Automatisk uppspelning",\r\n
DlgFlashChkLoop\t\t: "Upprepa/Loopa",\r\n
DlgFlashChkMenu\t\t: "Aktivera Flashmeny",\r\n
DlgFlashScale\t\t: "Skala",\r\n
DlgFlashScaleAll\t: "Visa allt",\r\n
DlgFlashScaleNoBorder\t: "Ingen ram",\r\n
DlgFlashScaleFit\t: "Exakt passning",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Länk",\r\n
DlgLnkInfoTab\t\t: "Länkinformation",\r\n
DlgLnkTargetTab\t\t: "Mål",\r\n
\r\n
DlgLnkType\t\t\t: "Länktyp",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Ankare i sidan",\r\n
DlgLnkTypeEMail\t\t: "E-post",\r\n
DlgLnkProto\t\t\t: "Protokoll",\r\n
DlgLnkProtoOther\t: "<övrigt>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Välj ett ankare",\r\n
DlgLnkAnchorByName\t: "efter ankarnamn",\r\n
DlgLnkAnchorById\t: "efter objektid",\r\n
DlgLnkNoAnchors\t\t: "(Inga ankare kunde hittas)",\r\n
DlgLnkEMail\t\t\t: "E-postadress",\r\n
DlgLnkEMailSubject\t: "Ämne",\r\n
DlgLnkEMailBody\t\t: "Innehåll",\r\n
DlgLnkUpload\t\t: "Ladda upp",\r\n
DlgLnkBtnUpload\t\t: "Skicka till servern",\r\n
\r\n
DlgLnkTarget\t\t: "Mål",\r\n
DlgLnkTargetFrame\t: "<ram>",\r\n
DlgLnkTargetPopup\t: "<popup-fönster>",\r\n
DlgLnkTargetBlank\t: "Nytt fönster (_blank)",\r\n
DlgLnkTargetParent\t: "Föregående Window (_parent)",\r\n
DlgLnkTargetSelf\t: "Detta fönstret (_self)",\r\n
DlgLnkTargetTop\t\t: "Översta fönstret (_top)",\r\n
DlgLnkTargetFrameName\t: "Målets ramnamn",\r\n
DlgLnkPopWinName\t: "Popup-fönstrets namn",\r\n
DlgLnkPopWinFeat\t: "Popup-fönstrets egenskaper",\r\n
DlgLnkPopResize\t\t: "Kan ändra storlek",\r\n
DlgLnkPopLocation\t: "Adressfält",\r\n
DlgLnkPopMenu\t\t: "Menyfält",\r\n
DlgLnkPopScroll\t\t: "Scrolllista",\r\n
DlgLnkPopStatus\t\t: "Statusfält",\r\n
DlgLnkPopToolbar\t: "Verktygsfält",\r\n
DlgLnkPopFullScrn\t: "Helskärm (endast IE)",\r\n
DlgLnkPopDependent\t: "Beroende (endest Netscape)",\r\n
DlgLnkPopWidth\t\t: "Bredd",\r\n
DlgLnkPopHeight\t\t: "Höjd",\r\n
DlgLnkPopLeft\t\t: "Position från vänster",\r\n
DlgLnkPopTop\t\t: "Position från sidans topp",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Var god ange länkens URL",\r\n
DlnLnkMsgNoEMail\t: "Var god ange E-postadress",\r\n
DlnLnkMsgNoAnchor\t: "Var god ange ett ankare",\r\n
DlnLnkMsgInvPopName\t: "Popup-rutans namn måste börja med en alfabetisk bokstav och får inte innehålla mellanslag",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Välj färg",\r\n
DlgColorBtnClear\t: "Rensa",\r\n
DlgColorHighlight\t: "Markera",\r\n
DlgColorSelected\t: "Vald",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Infoga smiley",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Välj utökat tecken",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Tabellegenskaper",\r\n
DlgTableRows\t\t: "Rader",\r\n
DlgTableColumns\t\t: "Kolumner",\r\n
DlgTableBorder\t\t: "Kantstorlek",\r\n
DlgTableAlign\t\t: "Justering",\r\n
DlgTableAlignNotSet\t: "<ej angivet>",\r\n
DlgTableAlignLeft\t: "Vänster",\r\n
DlgTableAlignCenter\t: "Centrerad",\r\n
DlgTableAlignRight\t: "Höger",\r\n
DlgTableWidth\t\t: "Bredd",\r\n
DlgTableWidthPx\t\t: "pixlar",\r\n
DlgTableWidthPc\t\t: "procent",\r\n
DlgTableHeight\t\t: "Höjd",\r\n
DlgTableCellSpace\t: "Cellavstånd",\r\n
DlgTableCellPad\t\t: "Cellutfyllnad",\r\n
DlgTableCaption\t\t: "Titel",\r\n
DlgTableSummary\t\t: "Sammanfattning",\r\n
DlgTableHeaders\t\t: "Rubrikrad",\r\n
DlgTableHeadersNone\t\t: "Ingen",\r\n
DlgTableHeadersColumn\t: "Första kolumnen",\r\n
DlgTableHeadersRow\t\t: "Första raden",\r\n
DlgTableHeadersBoth\t\t: "Båda",\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Cellegenskaper",\r\n
DlgCellWidth\t\t: "Bredd",\r\n
DlgCellWidthPx\t\t: "pixlar",\r\n
DlgCellWidthPc\t\t: "procent",\r\n
DlgCellHeight\t\t: "Höjd",\r\n
DlgCellWordWrap\t\t: "Automatisk radbrytning",\r\n
DlgCellWordWrapNotSet\t: "<Ej angivet>",\r\n
DlgCellWordWrapYes\t: "Ja",\r\n
DlgCellWordWrapNo\t: "Nej",\r\n
DlgCellHorAlign\t\t: "Horisontal justering",\r\n
DlgCellHorAlignNotSet\t: "<Ej angivet>",\r\n
DlgCellHorAlignLeft\t: "Vänster",\r\n
DlgCellHorAlignCenter\t: "Centrerad",\r\n
DlgCellHorAlignRight: "Höger",\r\n
DlgCellVerAlign\t\t: "Vertikal justering",\r\n
DlgCellVerAlignNotSet\t: "<Ej angivet>",\r\n
DlgCellVerAlignTop\t: "Topp",\r\n
DlgCellVerAlignMiddle\t: "Mitten",\r\n
DlgCellVerAlignBottom\t: "Nederkant",\r\n
DlgCellVerAlignBaseline\t: "Underst",\r\n
DlgCellType\t\t: "Cell Typ",\r\n
DlgCellTypeData\t\t: "Data",\r\n
DlgCellTypeHeader\t: "Titel",\r\n
DlgCellRowSpan\t\t: "Radomfång",\r\n
DlgCellCollSpan\t\t: "Kolumnomfång",\r\n
DlgCellBackColor\t: "Bakgrundsfärg",\r\n
DlgCellBorderColor\t: "Kantfärg",\r\n
DlgCellBtnSelect\t: "Välj...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Sök och ersätt",\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Sök",\r\n
DlgFindFindBtn\t\t: "Sök",\r\n
DlgFindNotFoundMsg\t: "Angiven text kunde ej hittas.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Ersätt",\r\n
DlgReplaceFindLbl\t\t: "Sök efter:",\r\n
DlgReplaceReplaceLbl\t: "Ersätt med:",\r\n
DlgReplaceCaseChk\t\t: "Skiftläge",\r\n
DlgReplaceReplaceBtn\t: "Ersätt",\r\n
DlgReplaceReplAllBtn\t: "Ersätt alla",\r\n
DlgReplaceWordChk\t\t: "Inkludera hela ord",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "Säkerhetsinställningar i Er webläsare tillåter inte åtgården Klipp ut. Använd (Ctrl+X) istället.",\r\n
PasteErrorCopy\t: "Säkerhetsinställningar i Er webläsare tillåter inte åtgården Kopiera. Använd (Ctrl+C) istället",\r\n
\r\n
PasteAsText\t\t: "Klistra in som vanlig text",\r\n
PasteFromWord\t: "Klistra in från Word",\r\n
\r\n
DlgPasteMsg2\t: "Var god och klistra in Er text i rutan nedan genom att använda (<STRONG>Ctrl+V</STRONG>) klicka sen på <STRONG>OK</STRONG>.",\r\n
DlgPasteSec\t\t: "På grund av din webläsares säkerhetsinställningar kan verktyget inte få åtkomst till urklippsdatan. Var god och använd detta fönster istället.",\r\n
DlgPasteIgnoreFont\t\t: "Ignorera typsnittsdefinitioner",\r\n
DlgPasteRemoveStyles\t: "Radera Stildefinitioner",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Automatisk",\r\n
ColorMoreColors\t: "Fler färger...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Dokumentegenskaper",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Ankaregenskaper",\r\n
DlgAnchorName\t\t: "Ankarnamn",\r\n
DlgAnchorErrorName\t: "Var god ange ett ankarnamn",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Saknas i ordlistan",\r\n
DlgSpellChangeTo\t\t: "Ändra till",\r\n
DlgSpellBtnIgnore\t\t: "Ignorera",\r\n
DlgSpellBtnIgnoreAll\t: "Ignorera alla",\r\n
DlgSpellBtnReplace\t\t: "Ersätt",\r\n
DlgSpellBtnReplaceAll\t: "Ersätt alla",\r\n
DlgSpellBtnUndo\t\t\t: "Ångra",\r\n
DlgSpellNoSuggestions\t: "- Förslag saknas -",\r\n
DlgSpellProgress\t\t: "Stavningskontroll pågår...",\r\n
DlgSpellNoMispell\t\t: "Stavningskontroll slutförd: Inga stavfel påträffades.",\r\n
DlgSpellNoChanges\t\t: "Stavningskontroll slutförd: Inga ord rättades.",\r\n
DlgSpellOneChange\t\t: "Stavningskontroll slutförd: Ett ord rättades.",\r\n
DlgSpellManyChanges\t\t: "Stavningskontroll slutförd: %1 ord rättades.",\r\n
\r\n
IeSpellDownload\t\t\t: "Stavningskontrollen är ej installerad. Vill du göra det nu?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Text (Värde)",\r\n
DlgButtonType\t\t: "Typ",\r\n
DlgButtonTypeBtn\t: "Knapp",\r\n
DlgButtonTypeSbm\t: "Skicka",\r\n
DlgButtonTypeRst\t: "Återställ",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Namn",\r\n
DlgCheckboxValue\t: "Värde",\r\n
DlgCheckboxSelected\t: "Vald",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Namn",\r\n
DlgFormAction\t: "Funktion",\r\n
DlgFormMethod\t: "Metod",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Namn",\r\n
DlgSelectValue\t\t: "Värde",\r\n
DlgSelectSize\t\t: "Storlek",\r\n
DlgSelectLines\t\t: "Linjer",\r\n
DlgSelectChkMulti\t: "Tillåt flerval",\r\n
DlgSelectOpAvail\t: "Befintliga val",\r\n
DlgSelectOpText\t\t: "Text",\r\n
DlgSelectOpValue\t: "Värde",\r\n
DlgSelectBtnAdd\t\t: "Lägg till",\r\n
DlgSelectBtnModify\t: "Redigera",\r\n
DlgSelectBtnUp\t\t: "Upp",\r\n
DlgSelectBtnDown\t: "Ner",\r\n
DlgSelectBtnSetValue : "Markera som valt värde",\r\n
DlgSelectBtnDelete\t: "Radera",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Namn",\r\n
DlgTextareaCols\t: "Kolumner",\r\n
DlgTextareaRows\t: "Rader",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Namn",\r\n
DlgTextValue\t\t: "Värde",\r\n
DlgTextCharWidth\t: "Teckenbredd",\r\n
DlgTextMaxChars\t\t: "Max antal tecken",\r\n
DlgTextType\t\t\t: "Typ",\r\n
DlgTextTypeText\t\t: "Text",\r\n
DlgTextTypePass\t\t: "Lösenord",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Namn",\r\n
DlgHiddenValue\t: "Värde",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Egenskaper för punktlista",\r\n
NumberedListProp\t: "Egenskaper för numrerad lista",\r\n
DlgLstStart\t\t\t: "Start",\r\n
DlgLstType\t\t\t: "Typ",\r\n
DlgLstTypeCircle\t: "Cirkel",\r\n
DlgLstTypeDisc\t\t: "Punkt",\r\n
DlgLstTypeSquare\t: "Ruta",\r\n
DlgLstTypeNumbers\t: "Nummer (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Gemener (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Versaler (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Små romerska siffror (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Stora romerska siffror (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Allmän",\r\n
DlgDocBackTab\t\t: "Bakgrund",\r\n
DlgDocColorsTab\t\t: "Färg och marginal",\r\n
DlgDocMetaTab\t\t: "Metadata",\r\n
\r\n
DlgDocPageTitle\t\t: "Sidtitel",\r\n
DlgDocLangDir\t\t: "Språkriktning",\r\n
DlgDocLangDirLTR\t: "Vänster till Höger",\r\n
DlgDocLangDirRTL\t: "Höger till Vänster",\r\n
DlgDocLangCode\t\t: "Språkkod",\r\n
DlgDocCharSet\t\t: "Teckenuppsättningar",\r\n
DlgDocCharSetCE\t\t: "Central Europa",\r\n
DlgDocCharSetCT\t\t: "Traditionell Kinesisk (Big5)",\r\n
DlgDocCharSetCR\t\t: "Kyrillisk",\r\n
DlgDocCharSetGR\t\t: "Grekiska",\r\n
DlgDocCharSetJP\t\t: "Japanska",\r\n
DlgDocCharSetKR\t\t: "Koreanska",\r\n
DlgDocCharSetTR\t\t: "Turkiska",\r\n
DlgDocCharSetUN\t\t: "Unicode (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "Väst Europa",\r\n
DlgDocCharSetOther\t: "Övriga teckenuppsättningar",\r\n
\r\n
DlgDocDocType\t\t: "Sidhuvud",\r\n
DlgDocDocTypeOther\t: "Övriga sidhuvuden",\r\n
DlgDocIncXHTML\t\t: "Inkludera XHTML deklaration",\r\n
DlgDocBgColor\t\t: "Bakgrundsfärg",\r\n
DlgDocBgImage\t\t: "Bakgrundsbildens URL",\r\n
DlgDocBgNoScroll\t: "Fast bakgrund",\r\n
DlgDocCText\t\t\t: "Text",\r\n
DlgDocCLink\t\t\t: "Länk",\r\n
DlgDocCVisited\t\t: "Besökt länk",\r\n
DlgDocCActive\t\t: "Aktiv länk",\r\n
DlgDocMargins\t\t: "Sidmarginal",\r\n
DlgDocMaTop\t\t\t: "Topp",\r\n
DlgDocMaLeft\t\t: "Vänster",\r\n
DlgDocMaRight\t\t: "Höger",\r\n
DlgDocMaBottom\t\t: "Botten",\r\n
DlgDocMeIndex\t\t: "Sidans nyckelord",\r\n
DlgDocMeDescr\t\t: "Sidans beskrivning",\r\n
DlgDocMeAuthor\t\t: "Författare",\r\n
DlgDocMeCopy\t\t: "Upphovsrätt",\r\n
DlgDocPreview\t\t: "Förhandsgranska",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Sidmallar",\r\n
DlgTemplatesTitle\t: "Sidmallar",\r\n
DlgTemplatesSelMsg\t: "Var god välj en mall att använda med editorn<br>(allt nuvarande innehåll raderas):",\r\n
DlgTemplatesLoading\t: "Laddar mallar. Var god vänta...",\r\n
DlgTemplatesNoTpl\t: "(Ingen mall är vald)",\r\n
DlgTemplatesReplace\t: "Ersätt aktuellt innehåll",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Om",\r\n
DlgAboutBrowserInfoTab\t: "Webläsare",\r\n
DlgAboutLicenseTab\t: "Licens",\r\n
DlgAboutVersion\t\t: "Version",\r\n
DlgAboutInfo\t\t: "För mer information se",\r\n
\r\n
// Div Dialog\r\n
DlgDivGeneralTab\t: "Allmänt",\r\n
DlgDivAdvancedTab\t: "Avancerat",\r\n
DlgDivStyle\t\t: "Stil",\r\n
DlgDivInlineStyle\t: "Inbäddad stil",\r\n
\r\n
ScaytTitle\t\t\t: "SCAYT",\r\n
ScaytTitleOptions\t: "Alternativ",\r\n
ScaytTitleLangs\t\t: "Språk",\r\n
ScaytTitleAbout\t\t: "Om"\r\n
};\r\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>18357</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
