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
            <value> <string>sk.js</string> </value>
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
 * Slovak language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Skryť panel nástrojov",\r\n
ToolbarExpand\t\t: "Zobraziť panel nástrojov",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Uložiť",\r\n
NewPage\t\t\t\t: "Nová stránka",\r\n
Preview\t\t\t\t: "Náhľad",\r\n
Cut\t\t\t\t\t: "Vystrihnúť",\r\n
Copy\t\t\t\t: "Kopírovať",\r\n
Paste\t\t\t\t: "Vložiť",\r\n
PasteText\t\t\t: "Vložiť ako čistý text",\r\n
PasteWord\t\t\t: "Vložiť z Wordu",\r\n
Print\t\t\t\t: "Tlač",\r\n
SelectAll\t\t\t: "Vybrať všetko",\r\n
RemoveFormat\t\t: "Odstrániť formátovanie",\r\n
InsertLinkLbl\t\t: "Odkaz",\r\n
InsertLink\t\t\t: "Vložiť/zmeniť odkaz",\r\n
RemoveLink\t\t\t: "Odstrániť odkaz",\r\n
VisitLink\t\t\t: "Ísť na odkaz",\r\n
Anchor\t\t\t\t: "Vložiť/zmeniť kotvu",\r\n
AnchorDelete\t\t: "Odstrániť kotvu",\r\n
InsertImageLbl\t\t: "Obrázok",\r\n
InsertImage\t\t\t: "Vložiť/zmeniť obrázok",\r\n
InsertFlashLbl\t\t: "Flash",\r\n
InsertFlash\t\t\t: "Vložiť/zmeniť Flash",\r\n
InsertTableLbl\t\t: "Tabuľka",\r\n
InsertTable\t\t\t: "Vložiť/zmeniť tabuľku",\r\n
InsertLineLbl\t\t: "Čiara",\r\n
InsertLine\t\t\t: "Vložiť vodorovnú čiaru",\r\n
InsertSpecialCharLbl: "Špeciálne znaky",\r\n
InsertSpecialChar\t: "Vložiť špeciálne znaky",\r\n
InsertSmileyLbl\t\t: "Smajlíky",\r\n
InsertSmiley\t\t: "Vložiť smajlíka",\r\n
About\t\t\t\t: "O aplikácii FCKeditor",\r\n
Bold\t\t\t\t: "Tučné",\r\n
Italic\t\t\t\t: "Kurzíva",\r\n
Underline\t\t\t: "Podčiarknuté",\r\n
StrikeThrough\t\t: "Prečiarknuté",\r\n
Subscript\t\t\t: "Dolný index",\r\n
Superscript\t\t\t: "Horný index",\r\n
LeftJustify\t\t\t: "Zarovnať vľavo",\r\n
CenterJustify\t\t: "Zarovnať na stred",\r\n
RightJustify\t\t: "Zarovnať vpravo",\r\n
BlockJustify\t\t: "Zarovnať do bloku",\r\n
DecreaseIndent\t\t: "Zmenšiť odsadenie",\r\n
IncreaseIndent\t\t: "Zväčšiť odsadenie",\r\n
Blockquote\t\t\t: "Citácia",\r\n
CreateDiv\t\t\t: "Vytvoriť Div kontajner",\r\n
EditDiv\t\t\t\t: "Editovať Div kontajner",\r\n
DeleteDiv\t\t\t: "Odstrániť Div kontajner",\r\n
Undo\t\t\t\t: "Späť",\r\n
Redo\t\t\t\t: "Znovu",\r\n
NumberedListLbl\t\t: "Číslovanie",\r\n
NumberedList\t\t: "Vložiť/odstrániť číslovanie",\r\n
BulletedListLbl\t\t: "Odrážky",\r\n
BulletedList\t\t: "Vložiť/odstraniť odrážky",\r\n
ShowTableBorders\t: "Zobraziť okraje tabuliek",\r\n
ShowDetails\t\t\t: "Zobraziť podrobnosti",\r\n
Style\t\t\t\t: "Štýl",\r\n
FontFormat\t\t\t: "Formát",\r\n
Font\t\t\t\t: "Písmo",\r\n
FontSize\t\t\t: "Veľkosť",\r\n
TextColor\t\t\t: "Farba textu",\r\n
BGColor\t\t\t\t: "Farba pozadia",\r\n
Source\t\t\t\t: "Zdroj",\r\n
Find\t\t\t\t: "Hľadať",\r\n
Replace\t\t\t\t: "Nahradiť",\r\n
SpellCheck\t\t\t: "Kontrola pravopisu",\r\n
UniversalKeyboard\t: "Univerzálna klávesnica",\r\n
PageBreakLbl\t\t: "Oddeľovač stránky",\r\n
PageBreak\t\t\t: "Vložiť oddeľovač stránky",\r\n
\r\n
Form\t\t\t: "Formulár",\r\n
Checkbox\t\t: "Zaškrtávacie políčko",\r\n
RadioButton\t\t: "Prepínač",\r\n
TextField\t\t: "Textové pole",\r\n
Textarea\t\t: "Textová oblasť",\r\n
HiddenField\t\t: "Skryté pole",\r\n
Button\t\t\t: "Tlačidlo",\r\n
SelectionField\t: "Rozbaľovací zoznam",\r\n
ImageButton\t\t: "Obrázkové tlačidlo",\r\n
\r\n
FitWindow\t\t: "Maximalizovať veľkosť okna editora",\r\n
ShowBlocks\t\t: "Ukázať bloky",\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Zmeniť odkaz",\r\n
CellCM\t\t\t\t: "Bunka",\r\n
RowCM\t\t\t\t: "Riadok",\r\n
ColumnCM\t\t\t: "Stĺpec",\r\n
InsertRowAfter\t\t: "Vložiť riadok pred",\r\n
InsertRowBefore\t\t: "Vložiť riadok za",\r\n
DeleteRows\t\t\t: "Vymazať riadok",\r\n
InsertColumnAfter\t: "Vložiť stĺpec pred",\r\n
InsertColumnBefore\t: "Vložiť stĺpec za",\r\n
DeleteColumns\t\t: "Zmazať stĺpec",\r\n
InsertCellAfter\t\t: "Vložiť bunku za",\r\n
InsertCellBefore\t: "Vložiť bunku pred",\r\n
DeleteCells\t\t\t: "Vymazať bunky",\r\n
MergeCells\t\t\t: "Zlúčiť bunky",\r\n
MergeRight\t\t\t: "Zlúčiť doprava",\r\n
MergeDown\t\t\t: "Zlúčiť dole",\r\n
HorizontalSplitCell\t: "Rozdeliť bunky horizontálne",\r\n
VerticalSplitCell\t: "Rozdeliť bunky vertikálne",\r\n
TableDelete\t\t\t: "Vymazať tabuľku",\r\n
CellProperties\t\t: "Vlastnosti bunky",\r\n
TableProperties\t\t: "Vlastnosti tabuľky",\r\n
ImageProperties\t\t: "Vlastnosti obrázku",\r\n
FlashProperties\t\t: "Vlastnosti Flashu",\r\n
\r\n
AnchorProp\t\t\t: "Vlastnosti kotvy",\r\n
ButtonProp\t\t\t: "Vlastnosti tlačidla",\r\n
CheckboxProp\t\t: "Vlastnosti zaškrtávacieho políčka",\r\n
HiddenFieldProp\t\t: "Vlastnosti skrytého poľa",\r\n
RadioButtonProp\t\t: "Vlastnosti prepínača",\r\n
ImageButtonProp\t\t: "Vlastnosti obrázkového tlačidla",\r\n
TextFieldProp\t\t: "Vlastnosti textového poľa",\r\n
SelectionFieldProp\t: "Vlastnosti rozbaľovacieho zoznamu",\r\n
TextareaProp\t\t: "Vlastnosti textovej oblasti",\r\n
FormProp\t\t\t: "Vlastnosti formulára",\r\n
\r\n
FontFormats\t\t\t: "Normálny;Formátovaný;Adresa;Nadpis 1;Nadpis 2;Nadpis 3;Nadpis 4;Nadpis 5;Nadpis 6;Odsek (DIV)",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "Prebieha spracovanie XHTML. Čakajte prosím...",\r\n
Done\t\t\t\t: "Dokončené.",\r\n
PasteWordConfirm\t: "Vyzerá to tak, že vkladaný text je kopírovaný z Wordu. Chcete ho pred vložením vyčistiť?",\r\n
NotCompatiblePaste\t: "Tento príkaz je dostupný len v prehliadači Internet Explorer verzie 5.5 alebo vyššej. Chcete vložiť text bez vyčistenia?",\r\n
UnknownToolbarItem\t: "Neznáma položka panela nástrojov \\"%1\\"",\r\n
UnknownCommand\t\t: "Neznámy príkaz \\"%1\\"",\r\n
NotImplemented\t\t: "Príkaz nie je implementovaný",\r\n
UnknownToolbarSet\t: "Panel nástrojov \\"%1\\" neexistuje",\r\n
NoActiveX\t\t\t: "Bezpečnostné nastavenia vášho prehliadača môžu obmedzovať niektoré funkcie editora. Pre ich plnú funkčnosť musíte zapnúť voľbu \\"Spúšťať ActiveX moduly a zásuvné moduly\\", inak sa môžete stretnúť s chybami a nefunkčnosťou niektorých funkcií.",\r\n
BrowseServerBlocked : "Prehliadač zdrojových prvkov nebolo možné otvoriť. Uistite sa, že máte vypnutú službu blokovania popup okien.",\r\n
DialogBlocked\t\t: "Dialógové okno nebolo možné otvoriť. Uistite sa, že máte vypnutú službu blokovania popup okien.",\r\n
VisitLinkBlocked\t: "Nebolo možné otvoriť nové okno. Uistite sa, že máte vypnutú službu blokovania popup okien.",\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "OK",\r\n
DlgBtnCancel\t\t: "Zrušiť",\r\n
DlgBtnClose\t\t\t: "Zavrieť",\r\n
DlgBtnBrowseServer\t: "Prechádzať server",\r\n
DlgAdvancedTag\t\t: "Rozšírené",\r\n
DlgOpOther\t\t\t: "<Ďalšie>",\r\n
DlgInfoTab\t\t\t: "Info",\r\n
DlgAlertUrl\t\t\t: "Prosím vložte URL",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<nenastavené>",\r\n
DlgGenId\t\t\t: "Id",\r\n
DlgGenLangDir\t\t: "Orientácia jazyka",\r\n
DlgGenLangDirLtr\t: "Zľava doprava (LTR)",\r\n
DlgGenLangDirRtl\t: "Sprava doľava (RTL)",\r\n
DlgGenLangCode\t\t: "Kód jazyka",\r\n
DlgGenAccessKey\t\t: "Prístupový kľúč",\r\n
DlgGenName\t\t\t: "Meno",\r\n
DlgGenTabIndex\t\t: "Poradie prvku",\r\n
DlgGenLongDescr\t\t: "Dlhý popis URL",\r\n
DlgGenClass\t\t\t: "Trieda štýlu",\r\n
DlgGenTitle\t\t\t: "Pomocný titulok",\r\n
DlgGenContType\t\t: "Pomocný typ obsahu",\r\n
DlgGenLinkCharset\t: "Priradená znaková sada",\r\n
DlgGenStyle\t\t\t: "Štýl",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Vlastnosti obrázku",\r\n
DlgImgInfoTab\t\t: "Informácie o obrázku",\r\n
DlgImgBtnUpload\t\t: "Odoslať na server",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "Odoslať",\r\n
DlgImgAlt\t\t\t: "Alternatívny text",\r\n
DlgImgWidth\t\t\t: "Šírka",\r\n
DlgImgHeight\t\t: "Výška",\r\n
DlgImgLockRatio\t\t: "Zámok",\r\n
DlgBtnResetSize\t\t: "Pôvodná veľkosť",\r\n
DlgImgBorder\t\t: "Okraje",\r\n
DlgImgHSpace\t\t: "H-medzera",\r\n
DlgImgVSpace\t\t: "V-medzera",\r\n
DlgImgAlign\t\t\t: "Zarovnanie",\r\n
DlgImgAlignLeft\t\t: "Vľavo",\r\n
DlgImgAlignAbsBottom: "Úplne dole",\r\n
DlgImgAlignAbsMiddle: "Do stredu",\r\n
DlgImgAlignBaseline\t: "Na základňu",\r\n
DlgImgAlignBottom\t: "Dole",\r\n
DlgImgAlignMiddle\t: "Na stred",\r\n
DlgImgAlignRight\t: "Vpravo",\r\n
DlgImgAlignTextTop\t: "Na horný okraj textu",\r\n
DlgImgAlignTop\t\t: "Nahor",\r\n
DlgImgPreview\t\t: "Náhľad",\r\n
DlgImgAlertUrl\t\t: "Zadajte prosím URL obrázku",\r\n
DlgImgLinkTab\t\t: "Odkaz",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Vlastnosti Flashu",\r\n
DlgFlashChkPlay\t\t: "Automatické prehrávanie",\r\n
DlgFlashChkLoop\t\t: "Opakovanie",\r\n
DlgFlashChkMenu\t\t: "Povoliť Flash Menu",\r\n
DlgFlashScale\t\t: "Mierka",\r\n
DlgFlashScaleAll\t: "Zobraziť mierku",\r\n
DlgFlashScaleNoBorder\t: "Bez okrajov",\r\n
DlgFlashScaleFit\t: "Roztiahnuť na celé",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Odkaz",\r\n
DlgLnkInfoTab\t\t: "Informácie o odkaze",\r\n
DlgLnkTargetTab\t\t: "Cieľ",\r\n
\r\n
DlgLnkType\t\t\t: "Typ odkazu",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Kotva v tejto stránke",\r\n
DlgLnkTypeEMail\t\t: "E-Mail",\r\n
DlgLnkProto\t\t\t: "Protokol",\r\n
DlgLnkProtoOther\t: "<iný>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Vybrať kotvu",\r\n
DlgLnkAnchorByName\t: "Podľa mena kotvy",\r\n
DlgLnkAnchorById\t: "Podľa Id objektu",\r\n
DlgLnkNoAnchors\t\t: "(V stránke nie je definovaná žiadna kotva)",\r\n
DlgLnkEMail\t\t\t: "E-Mailová adresa",\r\n
DlgLnkEMailSubject\t: "Predmet správy",\r\n
DlgLnkEMailBody\t\t: "Telo správy",\r\n
DlgLnkUpload\t\t: "Odoslať",\r\n
DlgLnkBtnUpload\t\t: "Odoslať na server",\r\n
\r\n
DlgLnkTarget\t\t: "Cieľ",\r\n
DlgLnkTargetFrame\t: "<rámec>",\r\n
DlgLnkTargetPopup\t: "<vyskakovacie okno>",\r\n
DlgLnkTargetBlank\t: "Nové okno (_blank)",\r\n
DlgLnkTargetParent\t: "Rodičovské okno (_parent)",\r\n
DlgLnkTargetSelf\t: "Rovnaké okno (_self)",\r\n
DlgLnkTargetTop\t\t: "Hlavné okno (_top)",\r\n
DlgLnkTargetFrameName\t: "Meno rámu cieľa",\r\n
DlgLnkPopWinName\t: "Názov vyskakovacieho okna",\r\n
DlgLnkPopWinFeat\t: "Vlastnosti vyskakovacieho okna",\r\n
DlgLnkPopResize\t\t: "Meniteľná veľkosť",\r\n
DlgLnkPopLocation\t: "Panel umiestnenia",\r\n
DlgLnkPopMenu\t\t: "Panel ponuky",\r\n
DlgLnkPopScroll\t\t: "Posuvníky",\r\n
DlgLnkPopStatus\t\t: "Stavový riadok",\r\n
DlgLnkPopToolbar\t: "Panel nástrojov",\r\n
DlgLnkPopFullScrn\t: "Celá obrazovka (IE)",\r\n
DlgLnkPopDependent\t: "Závislosť (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Šírka",\r\n
DlgLnkPopHeight\t\t: "Výška",\r\n
DlgLnkPopLeft\t\t: "Ľavý okraj",\r\n
DlgLnkPopTop\t\t: "Horný okraj",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Zadajte prosím URL odkazu",\r\n
DlnLnkMsgNoEMail\t: "Zadajte prosím e-mailovú adresu",\r\n
DlnLnkMsgNoAnchor\t: "Vyberte prosím kotvu",\r\n
DlnLnkMsgInvPopName\t: "Názov vyskakovacieho okna sa musá začínať písmenom a nemôže obsahovať medzery",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Výber farby",\r\n
DlgColorBtnClear\t: "Vymazať",\r\n
DlgColorHighlight\t: "Zvýraznená",\r\n
DlgColorSelected\t: "Vybraná",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Vkladanie smajlíkov",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Výber špeciálneho znaku",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Vlastnosti tabuľky",\r\n
DlgTableRows\t\t: "Riadky",\r\n
DlgTableColumns\t\t: "Stĺpce",\r\n
DlgTableBorder\t\t: "Ohraničenie",\r\n
DlgTableAlign\t\t: "Zarovnanie",\r\n
DlgTableAlignNotSet\t: "<nenastavené>",\r\n
DlgTableAlignLeft\t: "Vľavo",\r\n
DlgTableAlignCenter\t: "Na stred",\r\n
DlgTableAlignRight\t: "Vpravo",\r\n
DlgTableWidth\t\t: "Šírka",\r\n
DlgTableWidthPx\t\t: "pixelov",\r\n
DlgTableWidthPc\t\t: "percent",\r\n
DlgTableHeight\t\t: "Výška",\r\n
DlgTableCellSpace\t: "Vzdialenosť buniek",\r\n
DlgTableCellPad\t\t: "Odsadenie obsahu",\r\n
DlgTableCaption\t\t: "Popis",\r\n
DlgTableSummary\t\t: "Prehľad",\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Vlastnosti bunky",\r\n
DlgCellWidth\t\t: "Šírka",\r\n
DlgCellWidthPx\t\t: "bodov",\r\n
DlgCellWidthPc\t\t: "percent",\r\n
DlgCellHeight\t\t: "Výška",\r\n
DlgCellWordWrap\t\t: "Zalamovannie",\r\n
DlgCellWordWrapNotSet\t: "<nenastavené>",\r\n
DlgCellWordWrapYes\t: "Áno",\r\n
DlgCellWordWrapNo\t: "Nie",\r\n
DlgCellHorAlign\t\t: "Vodorovné zarovnanie",\r\n
DlgCellHorAlignNotSet\t: "<nenastavené>",\r\n
DlgCellHorAlignLeft\t: "Vľavo",\r\n
DlgCellHorAlignCenter\t: "Na stred",\r\n
DlgCellHorAlignRight: "Vpravo",\r\n
DlgCellVerAlign\t\t: "Zvislé zarovnanie",\r\n
DlgCellVerAlignNotSet\t: "<nenastavené>",\r\n
DlgCellVerAlignTop\t: "Nahor",\r\n
DlgCellVerAlignMiddle\t: "Doprostred",\r\n
DlgCellVerAlignBottom\t: "Dole",\r\n
DlgCellVerAlignBaseline\t: "Na základňu",\r\n
DlgCellType\t\t: "Cell Type",\t//MISSING\r\n
DlgCellTypeData\t\t: "Data",\t//MISSING\r\n
DlgCellTypeHeader\t: "Header",\t//MISSING\r\n
DlgCellRowSpan\t\t: "Zlúčené riadky",\r\n
DlgCellCollSpan\t\t: "Zlúčené stĺpce",\r\n
DlgCellBackColor\t: "Farba pozadia",\r\n
DlgCellBorderColor\t: "Farba ohraničenia",\r\n
DlgCellBtnSelect\t: "Výber...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Nájsť a nahradiť",\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Hľadať",\r\n
DlgFindFindBtn\t\t: "Hľadať",\r\n
DlgFindNotFoundMsg\t: "Hľadaný text nebol nájdený.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Nahradiť",\r\n
DlgReplaceFindLbl\t\t: "Čo hľadať:",\r\n
DlgReplaceReplaceLbl\t: "Čím nahradiť:",\r\n
DlgReplaceCaseChk\t\t: "Rozlišovať malé/veľké písmená",\r\n
DlgReplaceReplaceBtn\t: "Nahradiť",\r\n
DlgReplaceReplAllBtn\t: "Nahradiť všetko",\r\n
DlgReplaceWordChk\t\t: "Len celé slová",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "Bezpečnostné nastavenia Vášho prehliadača nedovoľujú editoru spustiť funkciu pre vystrihnutie zvoleného textu do schránky. Prosím vystrihnite zvolený text do schránky pomocou klávesnice (Ctrl+X).",\r\n
PasteErrorCopy\t: "Bezpečnostné nastavenia Vášho prehliadača nedovoľujú editoru spustiť funkciu pre kopírovanie zvoleného textu do schránky. Prosím skopírujte zvolený text do schránky pomocou klávesnice (Ctrl+C).",\r\n
\r\n
PasteAsText\t\t: "Vložiť ako čistý text",\r\n
PasteFromWord\t: "Vložiť text z Wordu",\r\n
\r\n
DlgPasteMsg2\t: "Prosím vložte nasledovný rámček použitím klávesnice (<STRONG>Ctrl+V</STRONG>) a stlačte <STRONG>OK</STRONG>.",\r\n
DlgPasteSec\t\t: "Bezpečnostné nastavenia Vášho prehliadača nedovoľujú editoru pristupovať priamo k datám v schránke. Musíte ich vložiť znovu do tohto okna.",\r\n
DlgPasteIgnoreFont\t\t: "Ignorovať nastavenia typu písma",\r\n
DlgPasteRemoveStyles\t: "Odstrániť formátovanie",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Automaticky",\r\n
ColorMoreColors\t: "Viac farieb...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Vlastnosti dokumentu",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Vlastnosti kotvy",\r\n
DlgAnchorName\t\t: "Meno kotvy",\r\n
DlgAnchorErrorName\t: "Zadajte prosím meno kotvy",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Nie je v slovníku",\r\n
DlgSpellChangeTo\t\t: "Zmeniť na",\r\n
DlgSpellBtnIgnore\t\t: "Ignorovať",\r\n
DlgSpellBtnIgnoreAll\t: "Ignorovať všetko",\r\n
DlgSpellBtnReplace\t\t: "Prepísat",\r\n
DlgSpellBtnReplaceAll\t: "Prepísat všetko",\r\n
DlgSpellBtnUndo\t\t\t: "Späť",\r\n
DlgSpellNoSuggestions\t: "- Žiadny návrh -",\r\n
DlgSpellProgress\t\t: "Prebieha kontrola pravopisu...",\r\n
DlgSpellNoMispell\t\t: "Kontrola pravopisu dokončená: bez chýb",\r\n
DlgSpellNoChanges\t\t: "Kontrola pravopisu dokončená: žiadne slová nezmenené",\r\n
DlgSpellOneChange\t\t: "Kontrola pravopisu dokončená: zmenené jedno slovo",\r\n
DlgSpellManyChanges\t\t: "Kontrola pravopisu dokončená: zmenených %1 slov",\r\n
\r\n
IeSpellDownload\t\t\t: "Kontrola pravopisu nie je naištalovaná. Chcete ju hneď stiahnuť?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Text",\r\n
DlgButtonType\t\t: "Typ",\r\n
DlgButtonTypeBtn\t: "Tlačidlo",\r\n
DlgButtonTypeSbm\t: "Odoslať",\r\n
DlgButtonTypeRst\t: "Vymazať",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Názov",\r\n
DlgCheckboxValue\t: "Hodnota",\r\n
DlgCheckboxSelected\t: "Vybrané",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Názov",\r\n
DlgFormAction\t: "Akcie",\r\n
DlgFormMethod\t: "Metóda",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Názov",\r\n
DlgSelectValue\t\t: "Hodnota",\r\n
DlgSelectSize\t\t: "Veľkosť",\r\n
DlgSelectLines\t\t: "riadkov",\r\n
DlgSelectChkMulti\t: "Povoliť viacnásobný výber",\r\n
DlgSelectOpAvail\t: "Dostupné možnosti",\r\n
DlgSelectOpText\t\t: "Text",\r\n
DlgSelectOpValue\t: "Hodnota",\r\n
DlgSelectBtnAdd\t\t: "Pridať",\r\n
DlgSelectBtnModify\t: "Zmeniť",\r\n
DlgSelectBtnUp\t\t: "Hore",\r\n
DlgSelectBtnDown\t: "Dole",\r\n
DlgSelectBtnSetValue : "Nastaviť ako vybranú hodnotu",\r\n
DlgSelectBtnDelete\t: "Zmazať",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Názov",\r\n
DlgTextareaCols\t: "Stĺpce",\r\n
DlgTextareaRows\t: "Riadky",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Názov",\r\n
DlgTextValue\t\t: "Hodnota",\r\n
DlgTextCharWidth\t: "Šírka pola (znakov)",\r\n
DlgTextMaxChars\t\t: "Maximálny počet znakov",\r\n
DlgTextType\t\t\t: "Typ",\r\n
DlgTextTypeText\t\t: "Text",\r\n
DlgTextTypePass\t\t: "Heslo",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Názov",\r\n
DlgHiddenValue\t: "Hodnota",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Vlastnosti odrážok",\r\n
NumberedListProp\t: "Vlastnosti číslovania",\r\n
DlgLstStart\t\t\t: "Štart",\r\n
DlgLstType\t\t\t: "Typ",\r\n
DlgLstTypeCircle\t: "Krúžok",\r\n
DlgLstTypeDisc\t\t: "Disk",\r\n
DlgLstTypeSquare\t: "Štvorec",\r\n
DlgLstTypeNumbers\t: "Číslovanie (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Malé písmená (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Veľké písmená (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Malé rímske číslice (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Veľké rímske číslice (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Všeobecné",\r\n
DlgDocBackTab\t\t: "Pozadie",\r\n
DlgDocColorsTab\t\t: "Farby a okraje",\r\n
DlgDocMetaTab\t\t: "Meta Data",\r\n
\r\n
DlgDocPageTitle\t\t: "Titulok",\r\n
DlgDocLangDir\t\t: "Orientácie jazyka",\r\n
DlgDocLangDirLTR\t: "Zľava doprava (LTR)",\r\n
DlgDocLangDirRTL\t: "Sprava doľava (RTL)",\r\n
DlgDocLangCode\t\t: "Kód jazyka",\r\n
DlgDocCharSet\t\t: "Kódová stránka",\r\n
DlgDocCharSetCE\t\t: "Stredoeurópske",\r\n
DlgDocCharSetCT\t\t: "Čínština tradičná (Big5)",\r\n
DlgDocCharSetCR\t\t: "Cyrillika",\r\n
DlgDocCharSetGR\t\t: "Gréčtina",\r\n
DlgDocCharSetJP\t\t: "Japončina",\r\n
DlgDocCharSetKR\t\t: "Korejčina",\r\n
DlgDocCharSetTR\t\t: "Turečtina",\r\n
DlgDocCharSetUN\t\t: "Unicode (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "Západná európa",\r\n
DlgDocCharSetOther\t: "Iná kódová stránka",\r\n
\r\n
DlgDocDocType\t\t: "Typ záhlavia dokumentu",\r\n
DlgDocDocTypeOther\t: "Iný typ záhlavia dokumentu",\r\n
DlgDocIncXHTML\t\t: "Obsahuje deklarácie XHTML",\r\n
DlgDocBgColor\t\t: "Farba pozadia",\r\n
DlgDocBgImage\t\t: "URL adresa obrázku na pozadí",\r\n
DlgDocBgNoScroll\t: "Fixné pozadie",\r\n
DlgDocCText\t\t\t: "Text",\r\n
DlgDocCLink\t\t\t: "Odkaz",\r\n
DlgDocCVisited\t\t: "Navštívený odkaz",\r\n
DlgDocCActive\t\t: "Aktívny odkaz",\r\n
DlgDocMargins\t\t: "Okraje stránky",\r\n
DlgDocMaTop\t\t\t: "Horný",\r\n
DlgDocMaLeft\t\t: "Ľavý",\r\n
DlgDocMaRight\t\t: "Pravý",\r\n
DlgDocMaBottom\t\t: "Dolný",\r\n
DlgDocMeIndex\t\t: "Kľúčové slová pre indexovanie (oddelené čiarkou)",\r\n
DlgDocMeDescr\t\t: "Popis stránky",\r\n
DlgDocMeAuthor\t\t: "Autor",\r\n
DlgDocMeCopy\t\t: "Autorské práva",\r\n
DlgDocPreview\t\t: "Náhľad",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Šablóny",\r\n
DlgTemplatesTitle\t: "Šablóny obsahu",\r\n
DlgTemplatesSelMsg\t: "Prosím vyberte šablóny na otvorenie v editore<br>(súšasný obsah bude stratený):",\r\n
DlgTemplatesLoading\t: "Nahrávam zoznam šablón. Čakajte prosím...",\r\n
DlgTemplatesNoTpl\t: "(žiadne šablóny nenájdené)",\r\n
DlgTemplatesReplace\t: "Nahradiť aktuálny obsah",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "O aplikáci",\r\n
DlgAboutBrowserInfoTab\t: "Informácie o prehliadači",\r\n
DlgAboutLicenseTab\t: "Licencia",\r\n
DlgAboutVersion\t\t: "verzia",\r\n
DlgAboutInfo\t\t: "Viac informácií získate na",\r\n
\r\n
// Div Dialog\r\n
DlgDivGeneralTab\t: "Hlavné",\r\n
DlgDivAdvancedTab\t: "Rozšírené",\r\n
DlgDivStyle\t\t: "Štýl",\r\n
DlgDivInlineStyle\t: "Inline štýl",\r\n
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
            <value> <int>19566</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
