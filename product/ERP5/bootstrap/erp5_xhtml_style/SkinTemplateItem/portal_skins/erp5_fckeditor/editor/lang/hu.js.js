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
            <value> <string>ts83858910.13</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>hu.js</string> </value>
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
 * Hungarian language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Eszköztár elrejtése",\r\n
ToolbarExpand\t\t: "Eszköztár megjelenítése",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Mentés",\r\n
NewPage\t\t\t\t: "Új oldal",\r\n
Preview\t\t\t\t: "Előnézet",\r\n
Cut\t\t\t\t\t: "Kivágás",\r\n
Copy\t\t\t\t: "Másolás",\r\n
Paste\t\t\t\t: "Beillesztés",\r\n
PasteText\t\t\t: "Beillesztés formázás nélkül",\r\n
PasteWord\t\t\t: "Beillesztés Word-ből",\r\n
Print\t\t\t\t: "Nyomtatás",\r\n
SelectAll\t\t\t: "Mindent kijelöl",\r\n
RemoveFormat\t\t: "Formázás eltávolítása",\r\n
InsertLinkLbl\t\t: "Hivatkozás",\r\n
InsertLink\t\t\t: "Hivatkozás beillesztése/módosítása",\r\n
RemoveLink\t\t\t: "Hivatkozás törlése",\r\n
VisitLink\t\t\t: "Open Link",\t//MISSING\r\n
Anchor\t\t\t\t: "Horgony beillesztése/szerkesztése",\r\n
AnchorDelete\t\t: "Horgony eltávolítása",\r\n
InsertImageLbl\t\t: "Kép",\r\n
InsertImage\t\t\t: "Kép beillesztése/módosítása",\r\n
InsertFlashLbl\t\t: "Flash",\r\n
InsertFlash\t\t\t: "Flash beillesztése, módosítása",\r\n
InsertTableLbl\t\t: "Táblázat",\r\n
InsertTable\t\t\t: "Táblázat beillesztése/módosítása",\r\n
InsertLineLbl\t\t: "Vonal",\r\n
InsertLine\t\t\t: "Elválasztóvonal beillesztése",\r\n
InsertSpecialCharLbl: "Speciális karakter",\r\n
InsertSpecialChar\t: "Speciális karakter beillesztése",\r\n
InsertSmileyLbl\t\t: "Hangulatjelek",\r\n
InsertSmiley\t\t: "Hangulatjelek beillesztése",\r\n
About\t\t\t\t: "FCKeditor névjegy",\r\n
Bold\t\t\t\t: "Félkövér",\r\n
Italic\t\t\t\t: "Dőlt",\r\n
Underline\t\t\t: "Aláhúzott",\r\n
StrikeThrough\t\t: "Áthúzott",\r\n
Subscript\t\t\t: "Alsó index",\r\n
Superscript\t\t\t: "Felső index",\r\n
LeftJustify\t\t\t: "Balra",\r\n
CenterJustify\t\t: "Középre",\r\n
RightJustify\t\t: "Jobbra",\r\n
BlockJustify\t\t: "Sorkizárt",\r\n
DecreaseIndent\t\t: "Behúzás csökkentése",\r\n
IncreaseIndent\t\t: "Behúzás növelése",\r\n
Blockquote\t\t\t: "Idézet blokk",\r\n
CreateDiv\t\t\t: "Create Div Container",\t//MISSING\r\n
EditDiv\t\t\t\t: "Edit Div Container",\t//MISSING\r\n
DeleteDiv\t\t\t: "Remove Div Container",\t//MISSING\r\n
Undo\t\t\t\t: "Visszavonás",\r\n
Redo\t\t\t\t: "Ismétlés",\r\n
NumberedListLbl\t\t: "Számozás",\r\n
NumberedList\t\t: "Számozás beillesztése/törlése",\r\n
BulletedListLbl\t\t: "Felsorolás",\r\n
BulletedList\t\t: "Felsorolás beillesztése/törlése",\r\n
ShowTableBorders\t: "Táblázat szegély mutatása",\r\n
ShowDetails\t\t\t: "Részletek mutatása",\r\n
Style\t\t\t\t: "Stílus",\r\n
FontFormat\t\t\t: "Formátum",\r\n
Font\t\t\t\t: "Betűtípus",\r\n
FontSize\t\t\t: "Méret",\r\n
TextColor\t\t\t: "Betűszín",\r\n
BGColor\t\t\t\t: "Háttérszín",\r\n
Source\t\t\t\t: "Forráskód",\r\n
Find\t\t\t\t: "Keresés",\r\n
Replace\t\t\t\t: "Csere",\r\n
SpellCheck\t\t\t: "Helyesírás-ellenőrzés",\r\n
UniversalKeyboard\t: "Univerzális billentyűzet",\r\n
PageBreakLbl\t\t: "Oldaltörés",\r\n
PageBreak\t\t\t: "Oldaltörés beillesztése",\r\n
\r\n
Form\t\t\t: "Űrlap",\r\n
Checkbox\t\t: "Jelölőnégyzet",\r\n
RadioButton\t\t: "Választógomb",\r\n
TextField\t\t: "Szövegmező",\r\n
Textarea\t\t: "Szövegterület",\r\n
HiddenField\t\t: "Rejtettmező",\r\n
Button\t\t\t: "Gomb",\r\n
SelectionField\t: "Legördülő lista",\r\n
ImageButton\t\t: "Képgomb",\r\n
\r\n
FitWindow\t\t: "Maximalizálás",\r\n
ShowBlocks\t\t: "Blokkok megjelenítése",\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Hivatkozás módosítása",\r\n
CellCM\t\t\t\t: "Cella",\r\n
RowCM\t\t\t\t: "Sor",\r\n
ColumnCM\t\t\t: "Oszlop",\r\n
InsertRowAfter\t\t: "Sor beillesztése az aktuális sor mögé",\r\n
InsertRowBefore\t\t: "Sor beillesztése az aktuális sor elé",\r\n
DeleteRows\t\t\t: "Sorok törlése",\r\n
InsertColumnAfter\t: "Oszlop beillesztése az aktuális oszlop mögé",\r\n
InsertColumnBefore\t: "Oszlop beillesztése az aktuális oszlop elé",\r\n
DeleteColumns\t\t: "Oszlopok törlése",\r\n
InsertCellAfter\t\t: "Cella beillesztése az aktuális cella mögé",\r\n
InsertCellBefore\t: "Cella beillesztése az aktuális cella elé",\r\n
DeleteCells\t\t\t: "Cellák törlése",\r\n
MergeCells\t\t\t: "Cellák egyesítése",\r\n
MergeRight\t\t\t: "Cellák egyesítése jobbra",\r\n
MergeDown\t\t\t: "Cellák egyesítése lefelé",\r\n
HorizontalSplitCell\t: "Cellák szétválasztása vízszintesen",\r\n
VerticalSplitCell\t: "Cellák szétválasztása függőlegesen",\r\n
TableDelete\t\t\t: "Táblázat törlése",\r\n
CellProperties\t\t: "Cella tulajdonságai",\r\n
TableProperties\t\t: "Táblázat tulajdonságai",\r\n
ImageProperties\t\t: "Kép tulajdonságai",\r\n
FlashProperties\t\t: "Flash tulajdonságai",\r\n
\r\n
AnchorProp\t\t\t: "Horgony tulajdonságai",\r\n
ButtonProp\t\t\t: "Gomb tulajdonságai",\r\n
CheckboxProp\t\t: "Jelölőnégyzet tulajdonságai",\r\n
HiddenFieldProp\t\t: "Rejtett mező tulajdonságai",\r\n
RadioButtonProp\t\t: "Választógomb tulajdonságai",\r\n
ImageButtonProp\t\t: "Képgomb tulajdonságai",\r\n
TextFieldProp\t\t: "Szövegmező tulajdonságai",\r\n
SelectionFieldProp\t: "Legördülő lista tulajdonságai",\r\n
TextareaProp\t\t: "Szövegterület tulajdonságai",\r\n
FormProp\t\t\t: "Űrlap tulajdonságai",\r\n
\r\n
FontFormats\t\t\t: "Normál;Formázott;Címsor;Fejléc 1;Fejléc 2;Fejléc 3;Fejléc 4;Fejléc 5;Fejléc 6;Bekezdés (DIV)",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "XHTML feldolgozása. Kérem várjon...",\r\n
Done\t\t\t\t: "Kész",\r\n
PasteWordConfirm\t: "A beilleszteni kívánt szöveg Word-ből van másolva. El kívánja távolítani a formázást a beillesztés előtt?",\r\n
NotCompatiblePaste\t: "Ez a parancs csak Internet Explorer 5.5 verziótól használható. Megpróbálja beilleszteni a szöveget az eredeti formázással?",\r\n
UnknownToolbarItem\t: "Ismeretlen eszköztár elem \\"%1\\"",\r\n
UnknownCommand\t\t: "Ismeretlen parancs \\"%1\\"",\r\n
NotImplemented\t\t: "A parancs nem hajtható végre",\r\n
UnknownToolbarSet\t: "Az eszközkészlet \\"%1\\" nem létezik",\r\n
NoActiveX\t\t\t: "A böngésző biztonsági beállításai korlátozzák a szerkesztő lehetőségeit. Engedélyezni kell ezt az opciót: \\"Run ActiveX controls and plug-ins\\". Ettől függetlenül előfordulhatnak hibaüzenetek ill. bizonyos funkciók hiányozhatnak.",\r\n
BrowseServerBlocked : "Nem lehet megnyitni a fájlböngészőt. Bizonyosodjon meg róla, hogy a felbukkanó ablakok engedélyezve vannak.",\r\n
DialogBlocked\t\t: "Nem lehet megnyitni a párbeszédablakot. Bizonyosodjon meg róla, hogy a felbukkanó ablakok engedélyezve vannak.",\r\n
VisitLinkBlocked\t: "It was not possible to open a new window. Make sure all popup blockers are disabled.",\t//MISSING\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "Rendben",\r\n
DlgBtnCancel\t\t: "Mégsem",\r\n
DlgBtnClose\t\t\t: "Bezárás",\r\n
DlgBtnBrowseServer\t: "Böngészés a szerveren",\r\n
DlgAdvancedTag\t\t: "További opciók",\r\n
DlgOpOther\t\t\t: "Egyéb",\r\n
DlgInfoTab\t\t\t: "Alaptulajdonságok",\r\n
DlgAlertUrl\t\t\t: "Illessze be a webcímet",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<nincs beállítva>",\r\n
DlgGenId\t\t\t: "Azonosító",\r\n
DlgGenLangDir\t\t: "Írás iránya",\r\n
DlgGenLangDirLtr\t: "Balról jobbra",\r\n
DlgGenLangDirRtl\t: "Jobbról balra",\r\n
DlgGenLangCode\t\t: "Nyelv kódja",\r\n
DlgGenAccessKey\t\t: "Billentyűkombináció",\r\n
DlgGenName\t\t\t: "Név",\r\n
DlgGenTabIndex\t\t: "Tabulátor index",\r\n
DlgGenLongDescr\t\t: "Részletes leírás webcíme",\r\n
DlgGenClass\t\t\t: "Stíluskészlet",\r\n
DlgGenTitle\t\t\t: "Súgócimke",\r\n
DlgGenContType\t\t: "Súgó tartalomtípusa",\r\n
DlgGenLinkCharset\t: "Hivatkozott tartalom kódlapja",\r\n
DlgGenStyle\t\t\t: "Stílus",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Kép tulajdonságai",\r\n
DlgImgInfoTab\t\t: "Alaptulajdonságok",\r\n
DlgImgBtnUpload\t\t: "Küldés a szerverre",\r\n
DlgImgURL\t\t\t: "Hivatkozás",\r\n
DlgImgUpload\t\t: "Feltöltés",\r\n
DlgImgAlt\t\t\t: "Buborék szöveg",\r\n
DlgImgWidth\t\t\t: "Szélesség",\r\n
DlgImgHeight\t\t: "Magasság",\r\n
DlgImgLockRatio\t\t: "Arány megtartása",\r\n
DlgBtnResetSize\t\t: "Eredeti méret",\r\n
DlgImgBorder\t\t: "Keret",\r\n
DlgImgHSpace\t\t: "Vízsz. táv",\r\n
DlgImgVSpace\t\t: "Függ. táv",\r\n
DlgImgAlign\t\t\t: "Igazítás",\r\n
DlgImgAlignLeft\t\t: "Bal",\r\n
DlgImgAlignAbsBottom: "Legaljára",\r\n
DlgImgAlignAbsMiddle: "Közepére",\r\n
DlgImgAlignBaseline\t: "Alapvonalhoz",\r\n
DlgImgAlignBottom\t: "Aljára",\r\n
DlgImgAlignMiddle\t: "Középre",\r\n
DlgImgAlignRight\t: "Jobbra",\r\n
DlgImgAlignTextTop\t: "Szöveg tetejére",\r\n
DlgImgAlignTop\t\t: "Tetejére",\r\n
DlgImgPreview\t\t: "Előnézet",\r\n
DlgImgAlertUrl\t\t: "Töltse ki a kép webcímét",\r\n
DlgImgLinkTab\t\t: "Hivatkozás",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Flash tulajdonságai",\r\n
DlgFlashChkPlay\t\t: "Automata lejátszás",\r\n
DlgFlashChkLoop\t\t: "Folyamatosan",\r\n
DlgFlashChkMenu\t\t: "Flash menü engedélyezése",\r\n
DlgFlashScale\t\t: "Méretezés",\r\n
DlgFlashScaleAll\t: "Mindent mutat",\r\n
DlgFlashScaleNoBorder\t: "Keret nélkül",\r\n
DlgFlashScaleFit\t: "Teljes kitöltés",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Hivatkozás tulajdonságai",\r\n
DlgLnkInfoTab\t\t: "Alaptulajdonságok",\r\n
DlgLnkTargetTab\t\t: "Megjelenítés",\r\n
\r\n
DlgLnkType\t\t\t: "Hivatkozás típusa",\r\n
DlgLnkTypeURL\t\t: "Webcím",\r\n
DlgLnkTypeAnchor\t: "Horgony az oldalon",\r\n
DlgLnkTypeEMail\t\t: "E-Mail",\r\n
DlgLnkProto\t\t\t: "Protokoll",\r\n
DlgLnkProtoOther\t: "<más>",\r\n
DlgLnkURL\t\t\t: "Webcím",\r\n
DlgLnkAnchorSel\t\t: "Horgony választása",\r\n
DlgLnkAnchorByName\t: "Horgony név szerint",\r\n
DlgLnkAnchorById\t: "Azonosító szerint",\r\n
DlgLnkNoAnchors\t\t: "(Nincs horgony a dokumentumban)",\r\n
DlgLnkEMail\t\t\t: "E-Mail cím",\r\n
DlgLnkEMailSubject\t: "Üzenet tárgya",\r\n
DlgLnkEMailBody\t\t: "Üzenet",\r\n
DlgLnkUpload\t\t: "Feltöltés",\r\n
DlgLnkBtnUpload\t\t: "Küldés a szerverre",\r\n
\r\n
DlgLnkTarget\t\t: "Tartalom megjelenítése",\r\n
DlgLnkTargetFrame\t: "<keretben>",\r\n
DlgLnkTargetPopup\t: "<felugró ablakban>",\r\n
DlgLnkTargetBlank\t: "Új ablakban (_blank)",\r\n
DlgLnkTargetParent\t: "Szülő ablakban (_parent)",\r\n
DlgLnkTargetSelf\t: "Azonos ablakban (_self)",\r\n
DlgLnkTargetTop\t\t: "Legfelső ablakban (_top)",\r\n
DlgLnkTargetFrameName\t: "Keret neve",\r\n
DlgLnkPopWinName\t: "Felugró ablak neve",\r\n
DlgLnkPopWinFeat\t: "Felugró ablak jellemzői",\r\n
DlgLnkPopResize\t\t: "Méretezhető",\r\n
DlgLnkPopLocation\t: "Címsor",\r\n
DlgLnkPopMenu\t\t: "Menü sor",\r\n
DlgLnkPopScroll\t\t: "Gördítősáv",\r\n
DlgLnkPopStatus\t\t: "Állapotsor",\r\n
DlgLnkPopToolbar\t: "Eszköztár",\r\n
DlgLnkPopFullScrn\t: "Teljes képernyő (csak IE)",\r\n
DlgLnkPopDependent\t: "Szülőhöz kapcsolt (csak Netscape)",\r\n
DlgLnkPopWidth\t\t: "Szélesség",\r\n
DlgLnkPopHeight\t\t: "Magasság",\r\n
DlgLnkPopLeft\t\t: "Bal pozíció",\r\n
DlgLnkPopTop\t\t: "Felső pozíció",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Adja meg a hivatkozás webcímét",\r\n
DlnLnkMsgNoEMail\t: "Adja meg az E-Mail címet",\r\n
DlnLnkMsgNoAnchor\t: "Válasszon egy horgonyt",\r\n
DlnLnkMsgInvPopName\t: "A felbukkanó ablak neve alfanumerikus karakterrel kezdôdjön, valamint ne tartalmazzon szóközt",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Színválasztás",\r\n
DlgColorBtnClear\t: "Törlés",\r\n
DlgColorHighlight\t: "Előnézet",\r\n
DlgColorSelected\t: "Kiválasztott",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Hangulatjel beszúrása",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Speciális karakter választása",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Táblázat tulajdonságai",\r\n
DlgTableRows\t\t: "Sorok",\r\n
DlgTableColumns\t\t: "Oszlopok",\r\n
DlgTableBorder\t\t: "Szegélyméret",\r\n
DlgTableAlign\t\t: "Igazítás",\r\n
DlgTableAlignNotSet\t: "<Nincs beállítva>",\r\n
DlgTableAlignLeft\t: "Balra",\r\n
DlgTableAlignCenter\t: "Középre",\r\n
DlgTableAlignRight\t: "Jobbra",\r\n
DlgTableWidth\t\t: "Szélesség",\r\n
DlgTableWidthPx\t\t: "képpont",\r\n
DlgTableWidthPc\t\t: "százalék",\r\n
DlgTableHeight\t\t: "Magasság",\r\n
DlgTableCellSpace\t: "Cella térköz",\r\n
DlgTableCellPad\t\t: "Cella belső margó",\r\n
DlgTableCaption\t\t: "Felirat",\r\n
DlgTableSummary\t\t: "Leírás",\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Cella tulajdonságai",\r\n
DlgCellWidth\t\t: "Szélesség",\r\n
DlgCellWidthPx\t\t: "képpont",\r\n
DlgCellWidthPc\t\t: "százalék",\r\n
DlgCellHeight\t\t: "Magasság",\r\n
DlgCellWordWrap\t\t: "Sortörés",\r\n
DlgCellWordWrapNotSet\t: "<Nincs beállítva>",\r\n
DlgCellWordWrapYes\t: "Igen",\r\n
DlgCellWordWrapNo\t: "Nem",\r\n
DlgCellHorAlign\t\t: "Vízsz. igazítás",\r\n
DlgCellHorAlignNotSet\t: "<Nincs beállítva>",\r\n
DlgCellHorAlignLeft\t: "Balra",\r\n
DlgCellHorAlignCenter\t: "Középre",\r\n
DlgCellHorAlignRight: "Jobbra",\r\n
DlgCellVerAlign\t\t: "Függ. igazítás",\r\n
DlgCellVerAlignNotSet\t: "<Nincs beállítva>",\r\n
DlgCellVerAlignTop\t: "Tetejére",\r\n
DlgCellVerAlignMiddle\t: "Középre",\r\n
DlgCellVerAlignBottom\t: "Aljára",\r\n
DlgCellVerAlignBaseline\t: "Egyvonalba",\r\n
DlgCellType\t\t: "Cell Type",\t//MISSING\r\n
DlgCellTypeData\t\t: "Data",\t//MISSING\r\n
DlgCellTypeHeader\t: "Header",\t//MISSING\r\n
DlgCellRowSpan\t\t: "Sorok egyesítése",\r\n
DlgCellCollSpan\t\t: "Oszlopok egyesítése",\r\n
DlgCellBackColor\t: "Háttérszín",\r\n
DlgCellBorderColor\t: "Szegélyszín",\r\n
DlgCellBtnSelect\t: "Kiválasztás...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Keresés és csere",\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Keresés",\r\n
DlgFindFindBtn\t\t: "Keresés",\r\n
DlgFindNotFoundMsg\t: "A keresett szöveg nem található.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Csere",\r\n
DlgReplaceFindLbl\t\t: "Keresett szöveg:",\r\n
DlgReplaceReplaceLbl\t: "Csere erre:",\r\n
DlgReplaceCaseChk\t\t: "kis- és nagybetű megkülönböztetése",\r\n
DlgReplaceReplaceBtn\t: "Csere",\r\n
DlgReplaceReplAllBtn\t: "Az összes cseréje",\r\n
DlgReplaceWordChk\t\t: "csak ha ez a teljes szó",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "A böngésző biztonsági beállításai nem engedélyezik a szerkesztőnek, hogy végrehajtsa a kivágás műveletet. Használja az alábbi billentyűkombinációt (Ctrl+X).",\r\n
PasteErrorCopy\t: "A böngésző biztonsági beállításai nem engedélyezik a szerkesztőnek, hogy végrehajtsa a másolás műveletet. Használja az alábbi billentyűkombinációt (Ctrl+X).",\r\n
\r\n
PasteAsText\t\t: "Beillesztés formázatlan szövegként",\r\n
PasteFromWord\t: "Beillesztés Word-ből",\r\n
\r\n
DlgPasteMsg2\t: "Másolja be az alábbi mezőbe a <STRONG>Ctrl+V</STRONG> billentyűk lenyomásával, majd nyomjon <STRONG>Rendben</STRONG>-t.",\r\n
DlgPasteSec\t\t: "A böngésző biztonsági beállításai miatt a szerkesztő nem képes hozzáférni a vágólap adataihoz. Illeszd be újra ebben az ablakban.",\r\n
DlgPasteIgnoreFont\t\t: "Betű formázások megszüntetése",\r\n
DlgPasteRemoveStyles\t: "Stílusok eltávolítása",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Automatikus",\r\n
ColorMoreColors\t: "További színek...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Dokumentum tulajdonságai",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Horgony tulajdonságai",\r\n
DlgAnchorName\t\t: "Horgony neve",\r\n
DlgAnchorErrorName\t: "Kérem adja meg a horgony nevét",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Nincs a szótárban",\r\n
DlgSpellChangeTo\t\t: "Módosítás",\r\n
DlgSpellBtnIgnore\t\t: "Kihagyja",\r\n
DlgSpellBtnIgnoreAll\t: "Mindet kihagyja",\r\n
DlgSpellBtnReplace\t\t: "Csere",\r\n
DlgSpellBtnReplaceAll\t: "Összes cseréje",\r\n
DlgSpellBtnUndo\t\t\t: "Visszavonás",\r\n
DlgSpellNoSuggestions\t: "Nincs javaslat",\r\n
DlgSpellProgress\t\t: "Helyesírás-ellenőrzés folyamatban...",\r\n
DlgSpellNoMispell\t\t: "Helyesírás-ellenőrzés kész: Nem találtam hibát",\r\n
DlgSpellNoChanges\t\t: "Helyesírás-ellenőrzés kész: Nincs változtatott szó",\r\n
DlgSpellOneChange\t\t: "Helyesírás-ellenőrzés kész: Egy szó cserélve",\r\n
DlgSpellManyChanges\t\t: "Helyesírás-ellenőrzés kész: %1 szó cserélve",\r\n
\r\n
IeSpellDownload\t\t\t: "A helyesírás-ellenőrző nincs telepítve. Szeretné letölteni most?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Szöveg (Érték)",\r\n
DlgButtonType\t\t: "Típus",\r\n
DlgButtonTypeBtn\t: "Gomb",\r\n
DlgButtonTypeSbm\t: "Küldés",\r\n
DlgButtonTypeRst\t: "Alaphelyzet",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Név",\r\n
DlgCheckboxValue\t: "Érték",\r\n
DlgCheckboxSelected\t: "Kiválasztott",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Név",\r\n
DlgFormAction\t: "Adatfeldolgozást végző hivatkozás",\r\n
DlgFormMethod\t: "Adatküldés módja",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Név",\r\n
DlgSelectValue\t\t: "Érték",\r\n
DlgSelectSize\t\t: "Méret",\r\n
DlgSelectLines\t\t: "sor",\r\n
DlgSelectChkMulti\t: "több sor is kiválasztható",\r\n
DlgSelectOpAvail\t: "Elérhető opciók",\r\n
DlgSelectOpText\t\t: "Szöveg",\r\n
DlgSelectOpValue\t: "Érték",\r\n
DlgSelectBtnAdd\t\t: "Hozzáad",\r\n
DlgSelectBtnModify\t: "Módosít",\r\n
DlgSelectBtnUp\t\t: "Fel",\r\n
DlgSelectBtnDown\t: "Le",\r\n
DlgSelectBtnSetValue : "Legyen az alapértelmezett érték",\r\n
DlgSelectBtnDelete\t: "Töröl",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Név",\r\n
DlgTextareaCols\t: "Karakterek száma egy sorban",\r\n
DlgTextareaRows\t: "Sorok száma",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Név",\r\n
DlgTextValue\t\t: "Érték",\r\n
DlgTextCharWidth\t: "Megjelenített karakterek száma",\r\n
DlgTextMaxChars\t\t: "Maximális karakterszám",\r\n
DlgTextType\t\t\t: "Típus",\r\n
DlgTextTypeText\t\t: "Szöveg",\r\n
DlgTextTypePass\t\t: "Jelszó",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Név",\r\n
DlgHiddenValue\t: "Érték",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Felsorolás tulajdonságai",\r\n
NumberedListProp\t: "Számozás tulajdonságai",\r\n
DlgLstStart\t\t\t: "Start",\r\n
DlgLstType\t\t\t: "Formátum",\r\n
DlgLstTypeCircle\t: "Kör",\r\n
DlgLstTypeDisc\t\t: "Lemez",\r\n
DlgLstTypeSquare\t: "Négyzet",\r\n
DlgLstTypeNumbers\t: "Számok (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Kisbetűk (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Nagybetűk (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Kis római számok (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Nagy római számok (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Általános",\r\n
DlgDocBackTab\t\t: "Háttér",\r\n
DlgDocColorsTab\t\t: "Színek és margók",\r\n
DlgDocMetaTab\t\t: "Meta adatok",\r\n
\r\n
DlgDocPageTitle\t\t: "Oldalcím",\r\n
DlgDocLangDir\t\t: "Írás iránya",\r\n
DlgDocLangDirLTR\t: "Balról jobbra",\r\n
DlgDocLangDirRTL\t: "Jobbról balra",\r\n
DlgDocLangCode\t\t: "Nyelv kód",\r\n
DlgDocCharSet\t\t: "Karakterkódolás",\r\n
DlgDocCharSetCE\t\t: "Közép-Európai",\r\n
DlgDocCharSetCT\t\t: "Kínai Tradicionális (Big5)",\r\n
DlgDocCharSetCR\t\t: "Cyrill",\r\n
DlgDocCharSetGR\t\t: "Görög",\r\n
DlgDocCharSetJP\t\t: "Japán",\r\n
DlgDocCharSetKR\t\t: "Koreai",\r\n
DlgDocCharSetTR\t\t: "Török",\r\n
DlgDocCharSetUN\t\t: "Unicode (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "Nyugat-Európai",\r\n
DlgDocCharSetOther\t: "Más karakterkódolás",\r\n
\r\n
DlgDocDocType\t\t: "Dokumentum típus fejléc",\r\n
DlgDocDocTypeOther\t: "Más dokumentum típus fejléc",\r\n
DlgDocIncXHTML\t\t: "XHTML deklarációk beillesztése",\r\n
DlgDocBgColor\t\t: "Háttérszín",\r\n
DlgDocBgImage\t\t: "Háttérkép cím",\r\n
DlgDocBgNoScroll\t: "Nem gördíthető háttér",\r\n
DlgDocCText\t\t\t: "Szöveg",\r\n
DlgDocCLink\t\t\t: "Cím",\r\n
DlgDocCVisited\t\t: "Látogatott cím",\r\n
DlgDocCActive\t\t: "Aktív cím",\r\n
DlgDocMargins\t\t: "Oldal margók",\r\n
DlgDocMaTop\t\t\t: "Felső",\r\n
DlgDocMaLeft\t\t: "Bal",\r\n
DlgDocMaRight\t\t: "Jobb",\r\n
DlgDocMaBottom\t\t: "Alsó",\r\n
DlgDocMeIndex\t\t: "Dokumentum keresőszavak (vesszővel elválasztva)",\r\n
DlgDocMeDescr\t\t: "Dokumentum leírás",\r\n
DlgDocMeAuthor\t\t: "Szerző",\r\n
DlgDocMeCopy\t\t: "Szerzői jog",\r\n
DlgDocPreview\t\t: "Előnézet",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Sablonok",\r\n
DlgTemplatesTitle\t: "Elérhető sablonok",\r\n
DlgTemplatesSelMsg\t: "Válassza ki melyik sablon nyíljon meg a szerkesztőben<br>(a jelenlegi tartalom elveszik):",\r\n
DlgTemplatesLoading\t: "Sablon lista betöltése. Kis türelmet...",\r\n
DlgTemplatesNoTpl\t: "(Nincs sablon megadva)",\r\n
DlgTemplatesReplace\t: "Kicseréli a jelenlegi tartalmat",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Névjegy",\r\n
DlgAboutBrowserInfoTab\t: "Böngésző információ",\r\n
DlgAboutLicenseTab\t: "Licensz",\r\n
DlgAboutVersion\t\t: "verzió",\r\n
DlgAboutInfo\t\t: "További információkért látogasson el ide:",\r\n
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
            <value> <int>20193</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
