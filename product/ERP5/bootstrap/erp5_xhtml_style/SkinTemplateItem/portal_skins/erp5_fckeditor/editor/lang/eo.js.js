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
            <value> <string>eo.js</string> </value>
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
 * Esperanto language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Kaŝi Ilobreton",\r\n
ToolbarExpand\t\t: "Vidigi Ilojn",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Sekurigi",\r\n
NewPage\t\t\t\t: "Nova Paĝo",\r\n
Preview\t\t\t\t: "Vidigi Aspekton",\r\n
Cut\t\t\t\t\t: "Eltondi",\r\n
Copy\t\t\t\t: "Kopii",\r\n
Paste\t\t\t\t: "Interglui",\r\n
PasteText\t\t\t: "Interglui kiel Tekston",\r\n
PasteWord\t\t\t: "Interglui el Word",\r\n
Print\t\t\t\t: "Presi",\r\n
SelectAll\t\t\t: "Elekti ĉion",\r\n
RemoveFormat\t\t: "Forigi Formaton",\r\n
InsertLinkLbl\t\t: "Ligilo",\r\n
InsertLink\t\t\t: "Enmeti/Ŝanĝi Ligilon",\r\n
RemoveLink\t\t\t: "Forigi Ligilon",\r\n
VisitLink\t\t\t: "Open Link",\t//MISSING\r\n
Anchor\t\t\t\t: "Enmeti/Ŝanĝi Ankron",\r\n
AnchorDelete\t\t: "Remove Anchor",\t//MISSING\r\n
InsertImageLbl\t\t: "Bildo",\r\n
InsertImage\t\t\t: "Enmeti/Ŝanĝi Bildon",\r\n
InsertFlashLbl\t\t: "Flash",\t//MISSING\r\n
InsertFlash\t\t\t: "Insert/Edit Flash",\t//MISSING\r\n
InsertTableLbl\t\t: "Tabelo",\r\n
InsertTable\t\t\t: "Enmeti/Ŝanĝi Tabelon",\r\n
InsertLineLbl\t\t: "Horizonta Linio",\r\n
InsertLine\t\t\t: "Enmeti Horizonta Linio",\r\n
InsertSpecialCharLbl: "Speciala Signo",\r\n
InsertSpecialChar\t: "Enmeti Specialan Signon",\r\n
InsertSmileyLbl\t\t: "Mienvinjeto",\r\n
InsertSmiley\t\t: "Enmeti Mienvinjeton",\r\n
About\t\t\t\t: "Pri FCKeditor",\r\n
Bold\t\t\t\t: "Grasa",\r\n
Italic\t\t\t\t: "Kursiva",\r\n
Underline\t\t\t: "Substreko",\r\n
StrikeThrough\t\t: "Trastreko",\r\n
Subscript\t\t\t: "Subskribo",\r\n
Superscript\t\t\t: "Superskribo",\r\n
LeftJustify\t\t\t: "Maldekstrigi",\r\n
CenterJustify\t\t: "Centrigi",\r\n
RightJustify\t\t: "Dekstrigi",\r\n
BlockJustify\t\t: "Ĝisrandigi Ambaŭflanke",\r\n
DecreaseIndent\t\t: "Malpligrandigi Krommarĝenon",\r\n
IncreaseIndent\t\t: "Pligrandigi Krommarĝenon",\r\n
Blockquote\t\t\t: "Blockquote",\t//MISSING\r\n
CreateDiv\t\t\t: "Create Div Container",\t//MISSING\r\n
EditDiv\t\t\t\t: "Edit Div Container",\t//MISSING\r\n
DeleteDiv\t\t\t: "Remove Div Container",\t//MISSING\r\n
Undo\t\t\t\t: "Malfari",\r\n
Redo\t\t\t\t: "Refari",\r\n
NumberedListLbl\t\t: "Numera Listo",\r\n
NumberedList\t\t: "Enmeti/Forigi Numeran Liston",\r\n
BulletedListLbl\t\t: "Bula Listo",\r\n
BulletedList\t\t: "Enmeti/Forigi Bulan Liston",\r\n
ShowTableBorders\t: "Vidigi Borderojn de Tabelo",\r\n
ShowDetails\t\t\t: "Vidigi Detalojn",\r\n
Style\t\t\t\t: "Stilo",\r\n
FontFormat\t\t\t: "Formato",\r\n
Font\t\t\t\t: "Tiparo",\r\n
FontSize\t\t\t: "Grando",\r\n
TextColor\t\t\t: "Teksta Koloro",\r\n
BGColor\t\t\t\t: "Fona Koloro",\r\n
Source\t\t\t\t: "Fonto",\r\n
Find\t\t\t\t: "Serĉi",\r\n
Replace\t\t\t\t: "Anstataŭigi",\r\n
SpellCheck\t\t\t: "Literumada Kontrolilo",\r\n
UniversalKeyboard\t: "Universala Klavaro",\r\n
PageBreakLbl\t\t: "Page Break",\t//MISSING\r\n
PageBreak\t\t\t: "Insert Page Break",\t//MISSING\r\n
\r\n
Form\t\t\t: "Formularo",\r\n
Checkbox\t\t: "Markobutono",\r\n
RadioButton\t\t: "Radiobutono",\r\n
TextField\t\t: "Teksta kampo",\r\n
Textarea\t\t: "Teksta Areo",\r\n
HiddenField\t\t: "Kaŝita Kampo",\r\n
Button\t\t\t: "Butono",\r\n
SelectionField\t: "Elekta Kampo",\r\n
ImageButton\t\t: "Bildbutono",\r\n
\r\n
FitWindow\t\t: "Maximize the editor size",\t//MISSING\r\n
ShowBlocks\t\t: "Show Blocks",\t//MISSING\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Modifier Ligilon",\r\n
CellCM\t\t\t\t: "Cell",\t//MISSING\r\n
RowCM\t\t\t\t: "Row",\t//MISSING\r\n
ColumnCM\t\t\t: "Column",\t//MISSING\r\n
InsertRowAfter\t\t: "Insert Row After",\t//MISSING\r\n
InsertRowBefore\t\t: "Insert Row Before",\t//MISSING\r\n
DeleteRows\t\t\t: "Forigi Liniojn",\r\n
InsertColumnAfter\t: "Insert Column After",\t//MISSING\r\n
InsertColumnBefore\t: "Insert Column Before",\t//MISSING\r\n
DeleteColumns\t\t: "Forigi Kolumnojn",\r\n
InsertCellAfter\t\t: "Insert Cell After",\t//MISSING\r\n
InsertCellBefore\t: "Insert Cell Before",\t//MISSING\r\n
DeleteCells\t\t\t: "Forigi Ĉelojn",\r\n
MergeCells\t\t\t: "Kunfandi Ĉelojn",\r\n
MergeRight\t\t\t: "Merge Right",\t//MISSING\r\n
MergeDown\t\t\t: "Merge Down",\t//MISSING\r\n
HorizontalSplitCell\t: "Split Cell Horizontally",\t//MISSING\r\n
VerticalSplitCell\t: "Split Cell Vertically",\t//MISSING\r\n
TableDelete\t\t\t: "Delete Table",\t//MISSING\r\n
CellProperties\t\t: "Atributoj de Ĉelo",\r\n
TableProperties\t\t: "Atributoj de Tabelo",\r\n
ImageProperties\t\t: "Atributoj de Bildo",\r\n
FlashProperties\t\t: "Flash Properties",\t//MISSING\r\n
\r\n
AnchorProp\t\t\t: "Ankraj Atributoj",\r\n
ButtonProp\t\t\t: "Butonaj Atributoj",\r\n
CheckboxProp\t\t: "Markobutonaj Atributoj",\r\n
HiddenFieldProp\t\t: "Atributoj de Kaŝita Kampo",\r\n
RadioButtonProp\t\t: "Radiobutonaj Atributoj",\r\n
ImageButtonProp\t\t: "Bildbutonaj Atributoj",\r\n
TextFieldProp\t\t: "Atributoj de Teksta Kampo",\r\n
SelectionFieldProp\t: "Atributoj de Elekta Kampo",\r\n
TextareaProp\t\t: "Atributoj de Teksta Areo",\r\n
FormProp\t\t\t: "Formularaj Atributoj",\r\n
\r\n
FontFormats\t\t\t: "Normala;Formatita;Adreso;Titolo 1;Titolo 2;Titolo 3;Titolo 4;Titolo 5;Titolo 6;Paragrafo (DIV)",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "Traktado de XHTML. Bonvolu pacienci...",\r\n
Done\t\t\t\t: "Finita",\r\n
PasteWordConfirm\t: "La algluota teksto ŝajnas esti Word-devena. Ĉu vi volas purigi ĝin antaŭ ol interglui?",\r\n
NotCompatiblePaste\t: "Tiu ĉi komando bezonas almenaŭ Internet Explorer 5.5. Ĉu vi volas daŭrigi sen purigado?",\r\n
UnknownToolbarItem\t: "Ilobretero nekonata \\"%1\\"",\r\n
UnknownCommand\t\t: "Komandonomo nekonata \\"%1\\"",\r\n
NotImplemented\t\t: "Komando ne ankoraŭ realigita",\r\n
UnknownToolbarSet\t: "La ilobreto \\"%1\\" ne ekzistas",\r\n
NoActiveX\t\t\t: "Your browser\'s security settings could limit some features of the editor. You must enable the option \\"Run ActiveX controls and plug-ins\\". You may experience errors and notice missing features.",\t//MISSING\r\n
BrowseServerBlocked : "The resources browser could not be opened. Make sure that all popup blockers are disabled.",\t//MISSING\r\n
DialogBlocked\t\t: "It was not possible to open the dialog window. Make sure all popup blockers are disabled.",\t//MISSING\r\n
VisitLinkBlocked\t: "It was not possible to open a new window. Make sure all popup blockers are disabled.",\t//MISSING\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "Akcepti",\r\n
DlgBtnCancel\t\t: "Rezigni",\r\n
DlgBtnClose\t\t\t: "Fermi",\r\n
DlgBtnBrowseServer\t: "Foliumi en la Servilo",\r\n
DlgAdvancedTag\t\t: "Speciala",\r\n
DlgOpOther\t\t\t: "<Alia>",\r\n
DlgInfoTab\t\t\t: "Info",\t//MISSING\r\n
DlgAlertUrl\t\t\t: "Please insert the URL",\t//MISSING\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<Defaŭlta>",\r\n
DlgGenId\t\t\t: "Id",\r\n
DlgGenLangDir\t\t: "Skribdirekto",\r\n
DlgGenLangDirLtr\t: "De maldekstro dekstren (LTR)",\r\n
DlgGenLangDirRtl\t: "De dekstro maldekstren (RTL)",\r\n
DlgGenLangCode\t\t: "Lingva Kodo",\r\n
DlgGenAccessKey\t\t: "Fulmoklavo",\r\n
DlgGenName\t\t\t: "Nomo",\r\n
DlgGenTabIndex\t\t: "Taba Ordo",\r\n
DlgGenLongDescr\t\t: "URL de Longa Priskribo",\r\n
DlgGenClass\t\t\t: "Klasoj de Stilfolioj",\r\n
DlgGenTitle\t\t\t: "Indika Titolo",\r\n
DlgGenContType\t\t: "Indika Enhavotipo",\r\n
DlgGenLinkCharset\t: "Signaro de la Ligita Rimedo",\r\n
DlgGenStyle\t\t\t: "Stilo",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Atributoj de Bildo",\r\n
DlgImgInfoTab\t\t: "Informoj pri Bildo",\r\n
DlgImgBtnUpload\t\t: "Sendu al Servilo",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "Alŝuti",\r\n
DlgImgAlt\t\t\t: "Anstataŭiga Teksto",\r\n
DlgImgWidth\t\t\t: "Larĝo",\r\n
DlgImgHeight\t\t: "Alto",\r\n
DlgImgLockRatio\t\t: "Konservi Proporcion",\r\n
DlgBtnResetSize\t\t: "Origina Grando",\r\n
DlgImgBorder\t\t: "Bordero",\r\n
DlgImgHSpace\t\t: "HSpaco",\r\n
DlgImgVSpace\t\t: "VSpaco",\r\n
DlgImgAlign\t\t\t: "Ĝisrandigo",\r\n
DlgImgAlignLeft\t\t: "Maldekstre",\r\n
DlgImgAlignAbsBottom: "Abs Malsupre",\r\n
DlgImgAlignAbsMiddle: "Abs Centre",\r\n
DlgImgAlignBaseline\t: "Je Malsupro de Teksto",\r\n
DlgImgAlignBottom\t: "Malsupre",\r\n
DlgImgAlignMiddle\t: "Centre",\r\n
DlgImgAlignRight\t: "Dekstre",\r\n
DlgImgAlignTextTop\t: "Je Supro de Teksto",\r\n
DlgImgAlignTop\t\t: "Supre",\r\n
DlgImgPreview\t\t: "Vidigi Aspekton",\r\n
DlgImgAlertUrl\t\t: "Bonvolu tajpi la URL de la bildo",\r\n
DlgImgLinkTab\t\t: "Link",\t//MISSING\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Flash Properties",\t//MISSING\r\n
DlgFlashChkPlay\t\t: "Auto Play",\t//MISSING\r\n
DlgFlashChkLoop\t\t: "Loop",\t//MISSING\r\n
DlgFlashChkMenu\t\t: "Enable Flash Menu",\t//MISSING\r\n
DlgFlashScale\t\t: "Scale",\t//MISSING\r\n
DlgFlashScaleAll\t: "Show all",\t//MISSING\r\n
DlgFlashScaleNoBorder\t: "No Border",\t//MISSING\r\n
DlgFlashScaleFit\t: "Exact Fit",\t//MISSING\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Ligilo",\r\n
DlgLnkInfoTab\t\t: "Informoj pri la Ligilo",\r\n
DlgLnkTargetTab\t\t: "Celo",\r\n
\r\n
DlgLnkType\t\t\t: "Tipo de Ligilo",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Ankri en tiu ĉi paĝo",\r\n
DlgLnkTypeEMail\t\t: "Retpoŝto",\r\n
DlgLnkProto\t\t\t: "Protokolo",\r\n
DlgLnkProtoOther\t: "<alia>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Elekti Ankron",\r\n
DlgLnkAnchorByName\t: "Per Ankronomo",\r\n
DlgLnkAnchorById\t: "Per Elementidentigilo",\r\n
DlgLnkNoAnchors\t\t: "<Ne disponeblas ankroj en la dokumento>",\r\n
DlgLnkEMail\t\t\t: "Retadreso",\r\n
DlgLnkEMailSubject\t: "Temlinio",\r\n
DlgLnkEMailBody\t\t: "Mesaĝa korpo",\r\n
DlgLnkUpload\t\t: "Alŝuti",\r\n
DlgLnkBtnUpload\t\t: "Sendi al Servilo",\r\n
\r\n
DlgLnkTarget\t\t: "Celo",\r\n
DlgLnkTargetFrame\t: "<kadro>",\r\n
DlgLnkTargetPopup\t: "<ŝprucfenestro>",\r\n
DlgLnkTargetBlank\t: "Nova Fenestro (_blank)",\r\n
DlgLnkTargetParent\t: "Gepatra Fenestro (_parent)",\r\n
DlgLnkTargetSelf\t: "Sama Fenestro (_self)",\r\n
DlgLnkTargetTop\t\t: "Plej Supra Fenestro (_top)",\r\n
DlgLnkTargetFrameName\t: "Nomo de Kadro",\r\n
DlgLnkPopWinName\t: "Nomo de Ŝprucfenestro",\r\n
DlgLnkPopWinFeat\t: "Atributoj de la Ŝprucfenestro",\r\n
DlgLnkPopResize\t\t: "Grando Ŝanĝebla",\r\n
DlgLnkPopLocation\t: "Adresobreto",\r\n
DlgLnkPopMenu\t\t: "Menubreto",\r\n
DlgLnkPopScroll\t\t: "Rulumlisteloj",\r\n
DlgLnkPopStatus\t\t: "Statobreto",\r\n
DlgLnkPopToolbar\t: "Ilobreto",\r\n
DlgLnkPopFullScrn\t: "Tutekrane (IE)",\r\n
DlgLnkPopDependent\t: "Dependa (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Larĝo",\r\n
DlgLnkPopHeight\t\t: "Alto",\r\n
DlgLnkPopLeft\t\t: "Pozicio de Maldekstro",\r\n
DlgLnkPopTop\t\t: "Pozicio de Supro",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Bonvolu entajpi la URL-on",\r\n
DlnLnkMsgNoEMail\t: "Bonvolu entajpi la retadreson",\r\n
DlnLnkMsgNoAnchor\t: "Bonvolu elekti ankron",\r\n
DlnLnkMsgInvPopName\t: "The popup name must begin with an alphabetic character and must not contain spaces",\t//MISSING\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Elekti",\r\n
DlgColorBtnClear\t: "Forigi",\r\n
DlgColorHighlight\t: "Emfazi",\r\n
DlgColorSelected\t: "Elektita",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Enmeti Mienvinjeton",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Enmeti Specialan Signon",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Atributoj de Tabelo",\r\n
DlgTableRows\t\t: "Linioj",\r\n
DlgTableColumns\t\t: "Kolumnoj",\r\n
DlgTableBorder\t\t: "Bordero",\r\n
DlgTableAlign\t\t: "Ĝisrandigo",\r\n
DlgTableAlignNotSet\t: "<Defaŭlte>",\r\n
DlgTableAlignLeft\t: "Maldekstre",\r\n
DlgTableAlignCenter\t: "Centre",\r\n
DlgTableAlignRight\t: "Dekstre",\r\n
DlgTableWidth\t\t: "Larĝo",\r\n
DlgTableWidthPx\t\t: "Bitbilderoj",\r\n
DlgTableWidthPc\t\t: "elcentoj",\r\n
DlgTableHeight\t\t: "Alto",\r\n
DlgTableCellSpace\t: "Interspacigo de Ĉeloj",\r\n
DlgTableCellPad\t\t: "Ĉirkaŭenhava Plenigado",\r\n
DlgTableCaption\t\t: "Titolo",\r\n
DlgTableSummary\t\t: "Summary",\t//MISSING\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Atributoj de Celo",\r\n
DlgCellWidth\t\t: "Larĝo",\r\n
DlgCellWidthPx\t\t: "bitbilderoj",\r\n
DlgCellWidthPc\t\t: "elcentoj",\r\n
DlgCellHeight\t\t: "Alto",\r\n
DlgCellWordWrap\t\t: "Linifaldo",\r\n
DlgCellWordWrapNotSet\t: "<Defaŭlte>",\r\n
DlgCellWordWrapYes\t: "Jes",\r\n
DlgCellWordWrapNo\t: "Ne",\r\n
DlgCellHorAlign\t\t: "Horizonta Ĝisrandigo",\r\n
DlgCellHorAlignNotSet\t: "<Defaŭlte>",\r\n
DlgCellHorAlignLeft\t: "Maldekstre",\r\n
DlgCellHorAlignCenter\t: "Centre",\r\n
DlgCellHorAlignRight: "Dekstre",\r\n
DlgCellVerAlign\t\t: "Vertikala Ĝisrandigo",\r\n
DlgCellVerAlignNotSet\t: "<Defaŭlte>",\r\n
DlgCellVerAlignTop\t: "Supre",\r\n
DlgCellVerAlignMiddle\t: "Centre",\r\n
DlgCellVerAlignBottom\t: "Malsupre",\r\n
DlgCellVerAlignBaseline\t: "Je Malsupro de Teksto",\r\n
DlgCellType\t\t: "Cell Type",\t//MISSING\r\n
DlgCellTypeData\t\t: "Data",\t//MISSING\r\n
DlgCellTypeHeader\t: "Header",\t//MISSING\r\n
DlgCellRowSpan\t\t: "Linioj Kunfanditaj",\r\n
DlgCellCollSpan\t\t: "Kolumnoj Kunfanditaj",\r\n
DlgCellBackColor\t: "Fono",\r\n
DlgCellBorderColor\t: "Bordero",\r\n
DlgCellBtnSelect\t: "Elekti...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Find and Replace",\t//MISSING\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Serĉi",\r\n
DlgFindFindBtn\t\t: "Serĉi",\r\n
DlgFindNotFoundMsg\t: "La celteksto ne estas trovita.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Anstataŭigi",\r\n
DlgReplaceFindLbl\t\t: "Serĉi:",\r\n
DlgReplaceReplaceLbl\t: "Anstataŭigi per:",\r\n
DlgReplaceCaseChk\t\t: "Kongruigi Usklecon",\r\n
DlgReplaceReplaceBtn\t: "Anstataŭigi",\r\n
DlgReplaceReplAllBtn\t: "Anstataŭigi Ĉiun",\r\n
DlgReplaceWordChk\t\t: "Tuta Vorto",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "La sekurecagordo de via TTT-legilo ne permesas, ke la redaktilo faras eltondajn operaciojn. Bonvolu uzi la klavaron por tio (ctrl-X).",\r\n
PasteErrorCopy\t: "La sekurecagordo de via TTT-legilo ne permesas, ke la redaktilo faras kopiajn operaciojn. Bonvolu uzi la klavaron por tio (ctrl-C).",\r\n
\r\n
PasteAsText\t\t: "Interglui kiel Tekston",\r\n
PasteFromWord\t: "Interglui el Word",\r\n
\r\n
DlgPasteMsg2\t: "Please paste inside the following box using the keyboard (<strong>Ctrl+V</strong>) and hit <strong>OK</strong>.",\t//MISSING\r\n
DlgPasteSec\t\t: "Because of your browser security settings, the editor is not able to access your clipboard data directly. You are required to paste it again in this window.",\t//MISSING\r\n
DlgPasteIgnoreFont\t\t: "Ignore Font Face definitions",\t//MISSING\r\n
DlgPasteRemoveStyles\t: "Remove Styles definitions",\t//MISSING\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Aŭtomata",\r\n
ColorMoreColors\t: "Pli da Koloroj...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Dokumentaj Atributoj",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Ankraj Atributoj",\r\n
DlgAnchorName\t\t: "Ankra Nomo",\r\n
DlgAnchorErrorName\t: "Bv tajpi la ankran nomon",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Ne trovita en la vortaro",\r\n
DlgSpellChangeTo\t\t: "Ŝanĝi al",\r\n
DlgSpellBtnIgnore\t\t: "Malatenti",\r\n
DlgSpellBtnIgnoreAll\t: "Malatenti Ĉiun",\r\n
DlgSpellBtnReplace\t\t: "Anstataŭigi",\r\n
DlgSpellBtnReplaceAll\t: "Anstataŭigi Ĉiun",\r\n
DlgSpellBtnUndo\t\t\t: "Malfari",\r\n
DlgSpellNoSuggestions\t: "- Neniu propono -",\r\n
DlgSpellProgress\t\t: "Literumkontrolado daŭras...",\r\n
DlgSpellNoMispell\t\t: "Literumkontrolado finita: neniu fuŝo trovita",\r\n
DlgSpellNoChanges\t\t: "Literumkontrolado finita: neniu vorto ŝanĝita",\r\n
DlgSpellOneChange\t\t: "Literumkontrolado finita: unu vorto ŝanĝita",\r\n
DlgSpellManyChanges\t\t: "Literumkontrolado finita: %1 vortoj ŝanĝitaj",\r\n
\r\n
IeSpellDownload\t\t\t: "Literumada Kontrolilo ne instalita. Ĉu vi volas elŝuti ĝin nun?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Teksto (Valoro)",\r\n
DlgButtonType\t\t: "Tipo",\r\n
DlgButtonTypeBtn\t: "Button",\t//MISSING\r\n
DlgButtonTypeSbm\t: "Submit",\t//MISSING\r\n
DlgButtonTypeRst\t: "Reset",\t//MISSING\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Nomo",\r\n
DlgCheckboxValue\t: "Valoro",\r\n
DlgCheckboxSelected\t: "Elektita",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Nomo",\r\n
DlgFormAction\t: "Ago",\r\n
DlgFormMethod\t: "Metodo",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Nomo",\r\n
DlgSelectValue\t\t: "Valoro",\r\n
DlgSelectSize\t\t: "Grando",\r\n
DlgSelectLines\t\t: "Linioj",\r\n
DlgSelectChkMulti\t: "Permesi Plurajn Elektojn",\r\n
DlgSelectOpAvail\t: "Elektoj Disponeblaj",\r\n
DlgSelectOpText\t\t: "Teksto",\r\n
DlgSelectOpValue\t: "Valoro",\r\n
DlgSelectBtnAdd\t\t: "Aldoni",\r\n
DlgSelectBtnModify\t: "Modifi",\r\n
DlgSelectBtnUp\t\t: "Supren",\r\n
DlgSelectBtnDown\t: "Malsupren",\r\n
DlgSelectBtnSetValue : "Agordi kiel Elektitan Valoron",\r\n
DlgSelectBtnDelete\t: "Forigi",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Nomo",\r\n
DlgTextareaCols\t: "Kolumnoj",\r\n
DlgTextareaRows\t: "Vicoj",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Nomo",\r\n
DlgTextValue\t\t: "Valoro",\r\n
DlgTextCharWidth\t: "Signolarĝo",\r\n
DlgTextMaxChars\t\t: "Maksimuma Nombro da Signoj",\r\n
DlgTextType\t\t\t: "Tipo",\r\n
DlgTextTypeText\t\t: "Teksto",\r\n
DlgTextTypePass\t\t: "Pasvorto",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Nomo",\r\n
DlgHiddenValue\t: "Valoro",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Atributoj de Bula Listo",\r\n
NumberedListProp\t: "Atributoj de Numera Listo",\r\n
DlgLstStart\t\t\t: "Start",\t//MISSING\r\n
DlgLstType\t\t\t: "Tipo",\r\n
DlgLstTypeCircle\t: "Cirklo",\r\n
DlgLstTypeDisc\t\t: "Disc",\t//MISSING\r\n
DlgLstTypeSquare\t: "Kvadrato",\r\n
DlgLstTypeNumbers\t: "Ciferoj (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Minusklaj Literoj (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Majusklaj Literoj (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Malgrandaj Romanaj Ciferoj (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Grandaj Romanaj Ciferoj (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Ĝeneralaĵoj",\r\n
DlgDocBackTab\t\t: "Fono",\r\n
DlgDocColorsTab\t\t: "Koloroj kaj Marĝenoj",\r\n
DlgDocMetaTab\t\t: "Metadatumoj",\r\n
\r\n
DlgDocPageTitle\t\t: "Paĝotitolo",\r\n
DlgDocLangDir\t\t: "Skribdirekto de la Lingvo",\r\n
DlgDocLangDirLTR\t: "De maldekstro dekstren (LTR)",\r\n
DlgDocLangDirRTL\t: "De dekstro maldekstren (LTR)",\r\n
DlgDocLangCode\t\t: "Lingvokodo",\r\n
DlgDocCharSet\t\t: "Signara Kodo",\r\n
DlgDocCharSetCE\t\t: "Central European",\t//MISSING\r\n
DlgDocCharSetCT\t\t: "Chinese Traditional (Big5)",\t//MISSING\r\n
DlgDocCharSetCR\t\t: "Cyrillic",\t//MISSING\r\n
DlgDocCharSetGR\t\t: "Greek",\t//MISSING\r\n
DlgDocCharSetJP\t\t: "Japanese",\t//MISSING\r\n
DlgDocCharSetKR\t\t: "Korean",\t//MISSING\r\n
DlgDocCharSetTR\t\t: "Turkish",\t//MISSING\r\n
DlgDocCharSetUN\t\t: "Unicode (UTF-8)",\t//MISSING\r\n
DlgDocCharSetWE\t\t: "Western European",\t//MISSING\r\n
DlgDocCharSetOther\t: "Alia Signara Kodo",\r\n
\r\n
DlgDocDocType\t\t: "Dokumenta Tipo",\r\n
DlgDocDocTypeOther\t: "Alia Dokumenta Tipo",\r\n
DlgDocIncXHTML\t\t: "Inkluzivi XHTML Deklaroj",\r\n
DlgDocBgColor\t\t: "Fona Koloro",\r\n
DlgDocBgImage\t\t: "URL de Fona Bildo",\r\n
DlgDocBgNoScroll\t: "Neruluma Fono",\r\n
DlgDocCText\t\t\t: "Teksto",\r\n
DlgDocCLink\t\t\t: "Ligilo",\r\n
DlgDocCVisited\t\t: "Vizitita Ligilo",\r\n
DlgDocCActive\t\t: "Aktiva Ligilo",\r\n
DlgDocMargins\t\t: "Paĝaj Marĝenoj",\r\n
DlgDocMaTop\t\t\t: "Supra",\r\n
DlgDocMaLeft\t\t: "Maldekstra",\r\n
DlgDocMaRight\t\t: "Dekstra",\r\n
DlgDocMaBottom\t\t: "Malsupra",\r\n
DlgDocMeIndex\t\t: "Ŝlosilvortoj de la Dokumento (apartigita de komoj)",\r\n
DlgDocMeDescr\t\t: "Dokumenta Priskribo",\r\n
DlgDocMeAuthor\t\t: "Verkinto",\r\n
DlgDocMeCopy\t\t: "Kopirajto",\r\n
DlgDocPreview\t\t: "Aspekto",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Templates",\t//MISSING\r\n
DlgTemplatesTitle\t: "Content Templates",\t//MISSING\r\n
DlgTemplatesSelMsg\t: "Please select the template to open in the editor<br />(the actual contents will be lost):",\t//MISSING\r\n
DlgTemplatesLoading\t: "Loading templates list. Please wait...",\t//MISSING\r\n
DlgTemplatesNoTpl\t: "(No templates defined)",\t//MISSING\r\n
DlgTemplatesReplace\t: "Replace actual contents",\t//MISSING\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Pri",\r\n
DlgAboutBrowserInfoTab\t: "Informoj pri TTT-legilo",\r\n
DlgAboutLicenseTab\t: "License",\t//MISSING\r\n
DlgAboutVersion\t\t: "versio",\r\n
DlgAboutInfo\t\t: "Por pli da informoj, vizitu",\r\n
\r\n
// Div Dialog\r\n
DlgDivGeneralTab\t: "General",\t//MISSING\r\n
DlgDivAdvancedTab\t: "Advanced",\t//MISSING\r\n
DlgDivStyle\t\t: "Style",\t//MISSING\r\n
DlgDivInlineStyle\t: "Inline Style",\t//MISSING\r\n
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
            <value> <int>19413</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
