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
            <value> <string>ro.js</string> </value>
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
 * Romanian language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Ascunde bara cu opţiuni",\r\n
ToolbarExpand\t\t: "Expandează bara cu opţiuni",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Salvează",\r\n
NewPage\t\t\t\t: "Pagină nouă",\r\n
Preview\t\t\t\t: "Previzualizare",\r\n
Cut\t\t\t\t\t: "Taie",\r\n
Copy\t\t\t\t: "Copiază",\r\n
Paste\t\t\t\t: "Adaugă",\r\n
PasteText\t\t\t: "Adaugă ca text simplu",\r\n
PasteWord\t\t\t: "Adaugă din Word",\r\n
Print\t\t\t\t: "Printează",\r\n
SelectAll\t\t\t: "Selectează tot",\r\n
RemoveFormat\t\t: "Înlătură formatarea",\r\n
InsertLinkLbl\t\t: "Link (Legătură web)",\r\n
InsertLink\t\t\t: "Inserează/Editează link (legătură web)",\r\n
RemoveLink\t\t\t: "Înlătură link (legătură web)",\r\n
VisitLink\t\t\t: "Open Link",\t//MISSING\r\n
Anchor\t\t\t\t: "Inserează/Editează ancoră",\r\n
AnchorDelete\t\t: "Şterge ancoră",\r\n
InsertImageLbl\t\t: "Imagine",\r\n
InsertImage\t\t\t: "Inserează/Editează imagine",\r\n
InsertFlashLbl\t\t: "Flash",\r\n
InsertFlash\t\t\t: "Inserează/Editează flash",\r\n
InsertTableLbl\t\t: "Tabel",\r\n
InsertTable\t\t\t: "Inserează/Editează tabel",\r\n
InsertLineLbl\t\t: "Linie",\r\n
InsertLine\t\t\t: "Inserează linie orizontă",\r\n
InsertSpecialCharLbl: "Caracter special",\r\n
InsertSpecialChar\t: "Inserează caracter special",\r\n
InsertSmileyLbl\t\t: "Figură expresivă (Emoticon)",\r\n
InsertSmiley\t\t: "Inserează Figură expresivă (Emoticon)",\r\n
About\t\t\t\t: "Despre FCKeditor",\r\n
Bold\t\t\t\t: "Îngroşat (bold)",\r\n
Italic\t\t\t\t: "Înclinat (italic)",\r\n
Underline\t\t\t: "Subliniat (underline)",\r\n
StrikeThrough\t\t: "Tăiat (strike through)",\r\n
Subscript\t\t\t: "Indice (subscript)",\r\n
Superscript\t\t\t: "Putere (superscript)",\r\n
LeftJustify\t\t\t: "Aliniere la stânga",\r\n
CenterJustify\t\t: "Aliniere centrală",\r\n
RightJustify\t\t: "Aliniere la dreapta",\r\n
BlockJustify\t\t: "Aliniere în bloc (Block Justify)",\r\n
DecreaseIndent\t\t: "Scade indentarea",\r\n
IncreaseIndent\t\t: "Creşte indentarea",\r\n
Blockquote\t\t\t: "Citat",\r\n
CreateDiv\t\t\t: "Create Div Container",\t//MISSING\r\n
EditDiv\t\t\t\t: "Edit Div Container",\t//MISSING\r\n
DeleteDiv\t\t\t: "Remove Div Container",\t//MISSING\r\n
Undo\t\t\t\t: "Starea anterioară (undo)",\r\n
Redo\t\t\t\t: "Starea ulterioară (redo)",\r\n
NumberedListLbl\t\t: "Listă numerotată",\r\n
NumberedList\t\t: "Inserează/Şterge listă numerotată",\r\n
BulletedListLbl\t\t: "Listă cu puncte",\r\n
BulletedList\t\t: "Inserează/Şterge listă cu puncte",\r\n
ShowTableBorders\t: "Arată marginile tabelului",\r\n
ShowDetails\t\t\t: "Arată detalii",\r\n
Style\t\t\t\t: "Stil",\r\n
FontFormat\t\t\t: "Formatare",\r\n
Font\t\t\t\t: "Font",\r\n
FontSize\t\t\t: "Mărime",\r\n
TextColor\t\t\t: "Culoarea textului",\r\n
BGColor\t\t\t\t: "Coloarea fundalului",\r\n
Source\t\t\t\t: "Sursa",\r\n
Find\t\t\t\t: "Găseşte",\r\n
Replace\t\t\t\t: "Înlocuieşte",\r\n
SpellCheck\t\t\t: "Verifică text",\r\n
UniversalKeyboard\t: "Tastatură universală",\r\n
PageBreakLbl\t\t: "Separator de pagină (Page Break)",\r\n
PageBreak\t\t\t: "Inserează separator de pagină (Page Break)",\r\n
\r\n
Form\t\t\t: "Formular (Form)",\r\n
Checkbox\t\t: "Bifă (Checkbox)",\r\n
RadioButton\t\t: "Buton radio (RadioButton)",\r\n
TextField\t\t: "Câmp text (TextField)",\r\n
Textarea\t\t: "Suprafaţă text (Textarea)",\r\n
HiddenField\t\t: "Câmp ascuns (HiddenField)",\r\n
Button\t\t\t: "Buton",\r\n
SelectionField\t: "Câmp selecţie (SelectionField)",\r\n
ImageButton\t\t: "Buton imagine (ImageButton)",\r\n
\r\n
FitWindow\t\t: "Maximizează mărimea editorului",\r\n
ShowBlocks\t\t: "Arată blocurile",\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Editează Link",\r\n
CellCM\t\t\t\t: "Celulă",\r\n
RowCM\t\t\t\t: "Linie",\r\n
ColumnCM\t\t\t: "Coloană",\r\n
InsertRowAfter\t\t: "Inserează linie după",\r\n
InsertRowBefore\t\t: "Inserează linie înainte",\r\n
DeleteRows\t\t\t: "Şterge linii",\r\n
InsertColumnAfter\t: "Inserează coloană după",\r\n
InsertColumnBefore\t: "Inserează coloană înainte",\r\n
DeleteColumns\t\t: "Şterge celule",\r\n
InsertCellAfter\t\t: "Inserează celulă după",\r\n
InsertCellBefore\t: "Inserează celulă înainte",\r\n
DeleteCells\t\t\t: "Şterge celule",\r\n
MergeCells\t\t\t: "Uneşte celule",\r\n
MergeRight\t\t\t: "Uneşte la dreapta",\r\n
MergeDown\t\t\t: "Uneşte jos",\r\n
HorizontalSplitCell\t: "Împarte celula pe orizontală",\r\n
VerticalSplitCell\t: "Împarte celula pe verticală",\r\n
TableDelete\t\t\t: "Şterge tabel",\r\n
CellProperties\t\t: "Proprietăţile celulei",\r\n
TableProperties\t\t: "Proprietăţile tabelului",\r\n
ImageProperties\t\t: "Proprietăţile imaginii",\r\n
FlashProperties\t\t: "Proprietăţile flash-ului",\r\n
\r\n
AnchorProp\t\t\t: "Proprietăţi ancoră",\r\n
ButtonProp\t\t\t: "Proprietăţi buton",\r\n
CheckboxProp\t\t: "Proprietăţi bifă (Checkbox)",\r\n
HiddenFieldProp\t\t: "Proprietăţi câmp ascuns (Hidden Field)",\r\n
RadioButtonProp\t\t: "Proprietăţi buton radio (Radio Button)",\r\n
ImageButtonProp\t\t: "Proprietăţi buton imagine (Image Button)",\r\n
TextFieldProp\t\t: "Proprietăţi câmp text (Text Field)",\r\n
SelectionFieldProp\t: "Proprietăţi câmp selecţie (Selection Field)",\r\n
TextareaProp\t\t: "Proprietăţi suprafaţă text (Textarea)",\r\n
FormProp\t\t\t: "Proprietăţi formular (Form)",\r\n
\r\n
FontFormats\t\t\t: "Normal;Formatted;Address;Heading 1;Heading 2;Heading 3;Heading 4;Heading 5;Heading 6;Normal (DIV)",\t//MISSING\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "Procesăm XHTML. Vă rugăm aşteptaţi...",\r\n
Done\t\t\t\t: "Am terminat",\r\n
PasteWordConfirm\t: "Textul pe care doriţi să-l adăugaţi pare a fi formatat pentru Word. Doriţi să-l curăţaţi de această formatare înainte de a-l adăuga?",\r\n
NotCompatiblePaste\t: "Această facilitate e disponibilă doar pentru Microsoft Internet Explorer, versiunea 5.5 sau ulterioară. Vreţi să-l adăugaţi fără a-i fi înlăturat formatarea?",\r\n
UnknownToolbarItem\t: "Obiectul \\"%1\\" din bara cu opţiuni necunoscut",\r\n
UnknownCommand\t\t: "Comanda \\"%1\\" necunoscută",\r\n
NotImplemented\t\t: "Comandă neimplementată",\r\n
UnknownToolbarSet\t: "Grupul din bara cu opţiuni \\"%1\\" nu există",\r\n
NoActiveX\t\t\t: "Setările de securitate ale programului dvs. cu care navigaţi pe internet (browser) pot limita anumite funcţionalităţi ale editorului. Pentru a evita asta, trebuie să activaţi opţiunea \\"Run ActiveX controls and plug-ins\\". Poate veţi întâlni erori sau veţi observa funcţionalităţi lipsă.",\r\n
BrowseServerBlocked : "The resources browser could not be opened. Asiguraţi-vă că nu e activ niciun \\"popup blocker\\" (funcţionalitate a programului de navigat (browser) sau a unui plug-in al acestuia de a bloca deschiderea unui noi ferestre).",\r\n
DialogBlocked\t\t: "Nu a fost posibilă deschiderea unei ferestre de dialog. Asiguraţi-vă că nu e activ niciun \\"popup blocker\\" (funcţionalitate a programului de navigat (browser) sau a unui plug-in al acestuia de a bloca deschiderea unui noi ferestre).",\r\n
VisitLinkBlocked\t: "It was not possible to open a new window. Make sure all popup blockers are disabled.",\t//MISSING\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "Bine",\r\n
DlgBtnCancel\t\t: "Anulare",\r\n
DlgBtnClose\t\t\t: "Închidere",\r\n
DlgBtnBrowseServer\t: "Răsfoieşte server",\r\n
DlgAdvancedTag\t\t: "Avansat",\r\n
DlgOpOther\t\t\t: "<Altul>",\r\n
DlgInfoTab\t\t\t: "Informaţii",\r\n
DlgAlertUrl\t\t\t: "Vă rugăm să scrieţi URL-ul",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<nesetat>",\r\n
DlgGenId\t\t\t: "Id",\r\n
DlgGenLangDir\t\t: "Direcţia cuvintelor",\r\n
DlgGenLangDirLtr\t: "stânga-dreapta (LTR)",\r\n
DlgGenLangDirRtl\t: "dreapta-stânga (RTL)",\r\n
DlgGenLangCode\t\t: "Codul limbii",\r\n
DlgGenAccessKey\t\t: "Tasta de acces",\r\n
DlgGenName\t\t\t: "Nume",\r\n
DlgGenTabIndex\t\t: "Indexul tabului",\r\n
DlgGenLongDescr\t\t: "Descrierea lungă URL",\r\n
DlgGenClass\t\t\t: "Clasele cu stilul paginii (CSS)",\r\n
DlgGenTitle\t\t\t: "Titlul consultativ",\r\n
DlgGenContType\t\t: "Tipul consultativ al titlului",\r\n
DlgGenLinkCharset\t: "Setul de caractere al resursei legate",\r\n
DlgGenStyle\t\t\t: "Stil",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Proprietăţile imaginii",\r\n
DlgImgInfoTab\t\t: "Informaţii despre imagine",\r\n
DlgImgBtnUpload\t\t: "Trimite la server",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "Încarcă",\r\n
DlgImgAlt\t\t\t: "Text alternativ",\r\n
DlgImgWidth\t\t\t: "Lăţime",\r\n
DlgImgHeight\t\t: "Înălţime",\r\n
DlgImgLockRatio\t\t: "Păstrează proporţiile",\r\n
DlgBtnResetSize\t\t: "Resetează mărimea",\r\n
DlgImgBorder\t\t: "Margine",\r\n
DlgImgHSpace\t\t: "HSpace",\r\n
DlgImgVSpace\t\t: "VSpace",\r\n
DlgImgAlign\t\t\t: "Aliniere",\r\n
DlgImgAlignLeft\t\t: "Stânga",\r\n
DlgImgAlignAbsBottom: "Jos absolut (Abs Bottom)",\r\n
DlgImgAlignAbsMiddle: "Mijloc absolut (Abs Middle)",\r\n
DlgImgAlignBaseline\t: "Linia de jos (Baseline)",\r\n
DlgImgAlignBottom\t: "Jos",\r\n
DlgImgAlignMiddle\t: "Mijloc",\r\n
DlgImgAlignRight\t: "Dreapta",\r\n
DlgImgAlignTextTop\t: "Text sus",\r\n
DlgImgAlignTop\t\t: "Sus",\r\n
DlgImgPreview\t\t: "Previzualizare",\r\n
DlgImgAlertUrl\t\t: "Vă rugăm să scrieţi URL-ul imaginii",\r\n
DlgImgLinkTab\t\t: "Link (Legătură web)",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Proprietăţile flash-ului",\r\n
DlgFlashChkPlay\t\t: "Rulează automat",\r\n
DlgFlashChkLoop\t\t: "Repetă (Loop)",\r\n
DlgFlashChkMenu\t\t: "Activează meniul flash",\r\n
DlgFlashScale\t\t: "Scală",\r\n
DlgFlashScaleAll\t: "Arată tot",\r\n
DlgFlashScaleNoBorder\t: "Fără margini (No border)",\r\n
DlgFlashScaleFit\t: "Potriveşte",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Link (Legătură web)",\r\n
DlgLnkInfoTab\t\t: "Informaţii despre link (Legătură web)",\r\n
DlgLnkTargetTab\t\t: "Ţintă (Target)",\r\n
\r\n
DlgLnkType\t\t\t: "Tipul link-ului (al legăturii web)",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Ancoră în această pagină",\r\n
DlgLnkTypeEMail\t\t: "E-Mail",\r\n
DlgLnkProto\t\t\t: "Protocol",\r\n
DlgLnkProtoOther\t: "<altul>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Selectaţi o ancoră",\r\n
DlgLnkAnchorByName\t: "după numele ancorei",\r\n
DlgLnkAnchorById\t: "după Id-ul elementului",\r\n
DlgLnkNoAnchors\t\t: "(Nicio ancoră disponibilă în document)",\r\n
DlgLnkEMail\t\t\t: "Adresă de e-mail",\r\n
DlgLnkEMailSubject\t: "Subiectul mesajului",\r\n
DlgLnkEMailBody\t\t: "Conţinutul mesajului",\r\n
DlgLnkUpload\t\t: "Încarcă",\r\n
DlgLnkBtnUpload\t\t: "Trimite la server",\r\n
\r\n
DlgLnkTarget\t\t: "Ţintă (Target)",\r\n
DlgLnkTargetFrame\t: "<frame>",\r\n
DlgLnkTargetPopup\t: "<fereastra popup>",\r\n
DlgLnkTargetBlank\t: "Fereastră nouă (_blank)",\r\n
DlgLnkTargetParent\t: "Fereastra părinte (_parent)",\r\n
DlgLnkTargetSelf\t: "Aceeaşi fereastră (_self)",\r\n
DlgLnkTargetTop\t\t: "Fereastra din topul ierarhiei (_top)",\r\n
DlgLnkTargetFrameName\t: "Numele frame-ului ţintă",\r\n
DlgLnkPopWinName\t: "Numele ferestrei popup",\r\n
DlgLnkPopWinFeat\t: "Proprietăţile ferestrei popup",\r\n
DlgLnkPopResize\t\t: "Scalabilă",\r\n
DlgLnkPopLocation\t: "Bara de locaţie",\r\n
DlgLnkPopMenu\t\t: "Bara de meniu",\r\n
DlgLnkPopScroll\t\t: "Scroll Bars",\r\n
DlgLnkPopStatus\t\t: "Bara de status",\r\n
DlgLnkPopToolbar\t: "Bara de opţiuni",\r\n
DlgLnkPopFullScrn\t: "Tot ecranul (Full Screen)(IE)",\r\n
DlgLnkPopDependent\t: "Dependent (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Lăţime",\r\n
DlgLnkPopHeight\t\t: "Înălţime",\r\n
DlgLnkPopLeft\t\t: "Poziţia la stânga",\r\n
DlgLnkPopTop\t\t: "Poziţia la dreapta",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Vă rugăm să scrieţi URL-ul",\r\n
DlnLnkMsgNoEMail\t: "Vă rugăm să scrieţi adresa de e-mail",\r\n
DlnLnkMsgNoAnchor\t: "Vă rugăm să selectaţi o ancoră",\r\n
DlnLnkMsgInvPopName\t: "Numele \'popup\'-ului trebuie să înceapă cu un caracter alfabetic şi trebuie să nu conţină spaţii",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Selectează culoare",\r\n
DlgColorBtnClear\t: "Curăţă",\r\n
DlgColorHighlight\t: "Subliniază (Highlight)",\r\n
DlgColorSelected\t: "Selectat",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Inserează o figură expresivă (Emoticon)",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Selectează caracter special",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Proprietăţile tabelului",\r\n
DlgTableRows\t\t: "Linii",\r\n
DlgTableColumns\t\t: "Coloane",\r\n
DlgTableBorder\t\t: "Mărimea marginii",\r\n
DlgTableAlign\t\t: "Aliniament",\r\n
DlgTableAlignNotSet\t: "<Nesetat>",\r\n
DlgTableAlignLeft\t: "Stânga",\r\n
DlgTableAlignCenter\t: "Centru",\r\n
DlgTableAlignRight\t: "Dreapta",\r\n
DlgTableWidth\t\t: "Lăţime",\r\n
DlgTableWidthPx\t\t: "pixeli",\r\n
DlgTableWidthPc\t\t: "procente",\r\n
DlgTableHeight\t\t: "Înălţime",\r\n
DlgTableCellSpace\t: "Spaţiu între celule",\r\n
DlgTableCellPad\t\t: "Spaţiu în cadrul celulei",\r\n
DlgTableCaption\t\t: "Titlu (Caption)",\r\n
DlgTableSummary\t\t: "Rezumat",\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Proprietăţile celulei",\r\n
DlgCellWidth\t\t: "Lăţime",\r\n
DlgCellWidthPx\t\t: "pixeli",\r\n
DlgCellWidthPc\t\t: "procente",\r\n
DlgCellHeight\t\t: "Înălţime",\r\n
DlgCellWordWrap\t\t: "Desparte cuvintele (Wrap)",\r\n
DlgCellWordWrapNotSet\t: "<Nesetat>",\r\n
DlgCellWordWrapYes\t: "Da",\r\n
DlgCellWordWrapNo\t: "Nu",\r\n
DlgCellHorAlign\t\t: "Aliniament orizontal",\r\n
DlgCellHorAlignNotSet\t: "<Nesetat>",\r\n
DlgCellHorAlignLeft\t: "Stânga",\r\n
DlgCellHorAlignCenter\t: "Centru",\r\n
DlgCellHorAlignRight: "Dreapta",\r\n
DlgCellVerAlign\t\t: "Aliniament vertical",\r\n
DlgCellVerAlignNotSet\t: "<Nesetat>",\r\n
DlgCellVerAlignTop\t: "Sus",\r\n
DlgCellVerAlignMiddle\t: "Mijloc",\r\n
DlgCellVerAlignBottom\t: "Jos",\r\n
DlgCellVerAlignBaseline\t: "Linia de jos (Baseline)",\r\n
DlgCellType\t\t: "Cell Type",\t//MISSING\r\n
DlgCellTypeData\t\t: "Data",\t//MISSING\r\n
DlgCellTypeHeader\t: "Header",\t//MISSING\r\n
DlgCellRowSpan\t\t: "Lungimea în linii (Span)",\r\n
DlgCellCollSpan\t\t: "Lungimea în coloane (Span)",\r\n
DlgCellBackColor\t: "Culoarea fundalului",\r\n
DlgCellBorderColor\t: "Culoarea marginii",\r\n
DlgCellBtnSelect\t: "Selectaţi...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Găseşte şi înlocuieşte",\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Găseşte",\r\n
DlgFindFindBtn\t\t: "Găseşte",\r\n
DlgFindNotFoundMsg\t: "Textul specificat nu a fost găsit.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Replace",\r\n
DlgReplaceFindLbl\t\t: "Găseşte:",\r\n
DlgReplaceReplaceLbl\t: "Înlocuieşte cu:",\r\n
DlgReplaceCaseChk\t\t: "Deosebeşte majuscule de minuscule (Match case)",\r\n
DlgReplaceReplaceBtn\t: "Înlocuieşte",\r\n
DlgReplaceReplAllBtn\t: "Înlocuieşte tot",\r\n
DlgReplaceWordChk\t\t: "Doar cuvintele întregi",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "Setările de securitate ale navigatorului (browser) pe care îl folosiţi nu permit editorului să execute automat operaţiunea de tăiere. Vă rugăm folosiţi tastatura (Ctrl+X).",\r\n
PasteErrorCopy\t: "Setările de securitate ale navigatorului (browser) pe care îl folosiţi nu permit editorului să execute automat operaţiunea de copiere. Vă rugăm folosiţi tastatura (Ctrl+C).",\r\n
\r\n
PasteAsText\t\t: "Adaugă ca text simplu (Plain Text)",\r\n
PasteFromWord\t: "Adaugă din Word",\r\n
\r\n
DlgPasteMsg2\t: "Vă rugăm adăugaţi în căsuţa următoare folosind tastatura (<STRONG>Ctrl+V</STRONG>) şi apăsaţi <STRONG>OK</STRONG>.",\r\n
DlgPasteSec\t\t: "Din cauza setărilor de securitate ale programului dvs. cu care navigaţi pe internet (browser), editorul nu poate accesa direct datele din clipboard. Va trebui să adăugaţi din nou datele în această fereastră.",\r\n
DlgPasteIgnoreFont\t\t: "Ignoră definiţiile Font Face",\r\n
DlgPasteRemoveStyles\t: "Şterge definiţiile stilurilor",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Automatic",\r\n
ColorMoreColors\t: "Mai multe culori...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Proprietăţile documentului",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Proprietăţile ancorei",\r\n
DlgAnchorName\t\t: "Numele ancorei",\r\n
DlgAnchorErrorName\t: "Vă rugăm scrieţi numele ancorei",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Nu e în dicţionar",\r\n
DlgSpellChangeTo\t\t: "Schimbă în",\r\n
DlgSpellBtnIgnore\t\t: "Ignoră",\r\n
DlgSpellBtnIgnoreAll\t: "Ignoră toate",\r\n
DlgSpellBtnReplace\t\t: "Înlocuieşte",\r\n
DlgSpellBtnReplaceAll\t: "Înlocuieşte tot",\r\n
DlgSpellBtnUndo\t\t\t: "Starea anterioară (undo)",\r\n
DlgSpellNoSuggestions\t: "- Fără sugestii -",\r\n
DlgSpellProgress\t\t: "Verificarea textului în desfăşurare...",\r\n
DlgSpellNoMispell\t\t: "Verificarea textului terminată: Nicio greşeală găsită",\r\n
DlgSpellNoChanges\t\t: "Verificarea textului terminată: Niciun cuvânt modificat",\r\n
DlgSpellOneChange\t\t: "Verificarea textului terminată: Un cuvânt modificat",\r\n
DlgSpellManyChanges\t\t: "Verificarea textului terminată: 1% cuvinte modificate",\r\n
\r\n
IeSpellDownload\t\t\t: "Unealta pentru verificat textul (Spell checker) neinstalată. Doriţi să o descărcaţi acum?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Text (Valoare)",\r\n
DlgButtonType\t\t: "Tip",\r\n
DlgButtonTypeBtn\t: "Button",\r\n
DlgButtonTypeSbm\t: "Submit",\r\n
DlgButtonTypeRst\t: "Reset",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Nume",\r\n
DlgCheckboxValue\t: "Valoare",\r\n
DlgCheckboxSelected\t: "Selectat",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Nume",\r\n
DlgFormAction\t: "Acţiune",\r\n
DlgFormMethod\t: "Metodă",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Nume",\r\n
DlgSelectValue\t\t: "Valoare",\r\n
DlgSelectSize\t\t: "Mărime",\r\n
DlgSelectLines\t\t: "linii",\r\n
DlgSelectChkMulti\t: "Permite selecţii multiple",\r\n
DlgSelectOpAvail\t: "Opţiuni disponibile",\r\n
DlgSelectOpText\t\t: "Text",\r\n
DlgSelectOpValue\t: "Valoare",\r\n
DlgSelectBtnAdd\t\t: "Adaugă",\r\n
DlgSelectBtnModify\t: "Modifică",\r\n
DlgSelectBtnUp\t\t: "Sus",\r\n
DlgSelectBtnDown\t: "Jos",\r\n
DlgSelectBtnSetValue : "Setează ca valoare selectată",\r\n
DlgSelectBtnDelete\t: "Şterge",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Nume",\r\n
DlgTextareaCols\t: "Coloane",\r\n
DlgTextareaRows\t: "Linii",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Nume",\r\n
DlgTextValue\t\t: "Valoare",\r\n
DlgTextCharWidth\t: "Lărgimea caracterului",\r\n
DlgTextMaxChars\t\t: "Caractere maxime",\r\n
DlgTextType\t\t\t: "Tip",\r\n
DlgTextTypeText\t\t: "Text",\r\n
DlgTextTypePass\t\t: "Parolă",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Nume",\r\n
DlgHiddenValue\t: "Valoare",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Proprietăţile listei punctate (Bulleted List)",\r\n
NumberedListProp\t: "Proprietăţile listei numerotate (Numbered List)",\r\n
DlgLstStart\t\t\t: "Start",\r\n
DlgLstType\t\t\t: "Tip",\r\n
DlgLstTypeCircle\t: "Cerc",\r\n
DlgLstTypeDisc\t\t: "Disc",\r\n
DlgLstTypeSquare\t: "Pătrat",\r\n
DlgLstTypeNumbers\t: "Numere (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Minuscule-litere mici (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Majuscule (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Cifre romane mici (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Cifre romane mari (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "General",\r\n
DlgDocBackTab\t\t: "Fundal",\r\n
DlgDocColorsTab\t\t: "Culori si margini",\r\n
DlgDocMetaTab\t\t: "Meta Data",\r\n
\r\n
DlgDocPageTitle\t\t: "Titlul paginii",\r\n
DlgDocLangDir\t\t: "Descrierea limbii",\r\n
DlgDocLangDirLTR\t: "stânga-dreapta (LTR)",\r\n
DlgDocLangDirRTL\t: "dreapta-stânga (RTL)",\r\n
DlgDocLangCode\t\t: "Codul limbii",\r\n
DlgDocCharSet\t\t: "Encoding setului de caractere",\r\n
DlgDocCharSetCE\t\t: "Central european",\r\n
DlgDocCharSetCT\t\t: "Chinezesc tradiţional (Big5)",\r\n
DlgDocCharSetCR\t\t: "Chirilic",\r\n
DlgDocCharSetGR\t\t: "Grecesc",\r\n
DlgDocCharSetJP\t\t: "Japonez",\r\n
DlgDocCharSetKR\t\t: "Corean",\r\n
DlgDocCharSetTR\t\t: "Turcesc",\r\n
DlgDocCharSetUN\t\t: "Unicode (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "Vest european",\r\n
DlgDocCharSetOther\t: "Alt encoding al setului de caractere",\r\n
\r\n
DlgDocDocType\t\t: "Document Type Heading",\r\n
DlgDocDocTypeOther\t: "Alt Document Type Heading",\r\n
DlgDocIncXHTML\t\t: "Include declaraţii XHTML",\r\n
DlgDocBgColor\t\t: "Culoarea fundalului (Background Color)",\r\n
DlgDocBgImage\t\t: "URL-ul imaginii din fundal (Background Image URL)",\r\n
DlgDocBgNoScroll\t: "Fundal neflotant, fix (Nonscrolling Background)",\r\n
DlgDocCText\t\t\t: "Text",\r\n
DlgDocCLink\t\t\t: "Link (Legătură web)",\r\n
DlgDocCVisited\t\t: "Link (Legătură web) vizitat",\r\n
DlgDocCActive\t\t: "Link (Legătură web) activ",\r\n
DlgDocMargins\t\t: "Marginile paginii",\r\n
DlgDocMaTop\t\t\t: "Sus",\r\n
DlgDocMaLeft\t\t: "Stânga",\r\n
DlgDocMaRight\t\t: "Dreapta",\r\n
DlgDocMaBottom\t\t: "Jos",\r\n
DlgDocMeIndex\t\t: "Cuvinte cheie după care se va indexa documentul (separate prin virgulă)",\r\n
DlgDocMeDescr\t\t: "Descrierea documentului",\r\n
DlgDocMeAuthor\t\t: "Autor",\r\n
DlgDocMeCopy\t\t: "Drepturi de autor",\r\n
DlgDocPreview\t\t: "Previzualizare",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Template-uri (şabloane)",\r\n
DlgTemplatesTitle\t: "Template-uri (şabloane) de conţinut",\r\n
DlgTemplatesSelMsg\t: "Vă rugăm selectaţi template-ul (şablonul) ce se va deschide în editor<br>(conţinutul actual va fi pierdut):",\r\n
DlgTemplatesLoading\t: "Se încarcă lista cu template-uri (şabloane). Vă rugăm aşteptaţi...",\r\n
DlgTemplatesNoTpl\t: "(Niciun template (şablon) definit)",\r\n
DlgTemplatesReplace\t: "Înlocuieşte cuprinsul actual",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Despre",\r\n
DlgAboutBrowserInfoTab\t: "Informaţii browser",\r\n
DlgAboutLicenseTab\t: "Licenţă",\r\n
DlgAboutVersion\t\t: "versiune",\r\n
DlgAboutInfo\t\t: "Pentru informaţii amănunţite, vizitaţi",\r\n
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
            <value> <int>21331</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
