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
            <value> <string>ts83858910.14</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>lt.js</string> </value>
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
 * Lithuanian language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Sutraukti mygtukų juostą",\r\n
ToolbarExpand\t\t: "Išplėsti mygtukų juostą",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Išsaugoti",\r\n
NewPage\t\t\t\t: "Naujas puslapis",\r\n
Preview\t\t\t\t: "Peržiūra",\r\n
Cut\t\t\t\t\t: "Iškirpti",\r\n
Copy\t\t\t\t: "Kopijuoti",\r\n
Paste\t\t\t\t: "Įdėti",\r\n
PasteText\t\t\t: "Įdėti kaip gryną tekstą",\r\n
PasteWord\t\t\t: "Įdėti iš Word",\r\n
Print\t\t\t\t: "Spausdinti",\r\n
SelectAll\t\t\t: "Pažymėti viską",\r\n
RemoveFormat\t\t: "Panaikinti formatą",\r\n
InsertLinkLbl\t\t: "Nuoroda",\r\n
InsertLink\t\t\t: "Įterpti/taisyti nuorodą",\r\n
RemoveLink\t\t\t: "Panaikinti nuorodą",\r\n
VisitLink\t\t\t: "Atidaryti nuorodą",\r\n
Anchor\t\t\t\t: "Įterpti/modifikuoti žymę",\r\n
AnchorDelete\t\t: "Naikinti žymę",\r\n
InsertImageLbl\t\t: "Vaizdas",\r\n
InsertImage\t\t\t: "Įterpti/taisyti vaizdą",\r\n
InsertFlashLbl\t\t: "Flash",\r\n
InsertFlash\t\t\t: "Įterpti/taisyti Flash",\r\n
InsertTableLbl\t\t: "Lentelė",\r\n
InsertTable\t\t\t: "Įterpti/taisyti lentelę",\r\n
InsertLineLbl\t\t: "Linija",\r\n
InsertLine\t\t\t: "Įterpti horizontalią liniją",\r\n
InsertSpecialCharLbl: "Spec. simbolis",\r\n
InsertSpecialChar\t: "Įterpti specialų simbolį",\r\n
InsertSmileyLbl\t\t: "Veideliai",\r\n
InsertSmiley\t\t: "Įterpti veidelį",\r\n
About\t\t\t\t: "Apie FCKeditor",\r\n
Bold\t\t\t\t: "Pusjuodis",\r\n
Italic\t\t\t\t: "Kursyvas",\r\n
Underline\t\t\t: "Pabrauktas",\r\n
StrikeThrough\t\t: "Perbrauktas",\r\n
Subscript\t\t\t: "Apatinis indeksas",\r\n
Superscript\t\t\t: "Viršutinis indeksas",\r\n
LeftJustify\t\t\t: "Lygiuoti kairę",\r\n
CenterJustify\t\t: "Centruoti",\r\n
RightJustify\t\t: "Lygiuoti dešinę",\r\n
BlockJustify\t\t: "Lygiuoti abi puses",\r\n
DecreaseIndent\t\t: "Sumažinti įtrauką",\r\n
IncreaseIndent\t\t: "Padidinti įtrauką",\r\n
Blockquote\t\t\t: "Citata",\r\n
CreateDiv\t\t\t: "Sukurti Div elementą",\r\n
EditDiv\t\t\t\t: "Reaguoti Div elementą",\r\n
DeleteDiv\t\t\t: "Šalinti Div elementą",\r\n
Undo\t\t\t\t: "Atšaukti",\r\n
Redo\t\t\t\t: "Atstatyti",\r\n
NumberedListLbl\t\t: "Numeruotas sąrašas",\r\n
NumberedList\t\t: "Įterpti/Panaikinti numeruotą sąrašą",\r\n
BulletedListLbl\t\t: "Suženklintas sąrašas",\r\n
BulletedList\t\t: "Įterpti/Panaikinti suženklintą sąrašą",\r\n
ShowTableBorders\t: "Rodyti lentelės rėmus",\r\n
ShowDetails\t\t\t: "Rodyti detales",\r\n
Style\t\t\t\t: "Stilius",\r\n
FontFormat\t\t\t: "Šrifto formatas",\r\n
Font\t\t\t\t: "Šriftas",\r\n
FontSize\t\t\t: "Šrifto dydis",\r\n
TextColor\t\t\t: "Teksto spalva",\r\n
BGColor\t\t\t\t: "Fono spalva",\r\n
Source\t\t\t\t: "Šaltinis",\r\n
Find\t\t\t\t: "Rasti",\r\n
Replace\t\t\t\t: "Pakeisti",\r\n
SpellCheck\t\t\t: "Rašybos tikrinimas",\r\n
UniversalKeyboard\t: "Universali klaviatūra",\r\n
PageBreakLbl\t\t: "Puslapių skirtukas",\r\n
PageBreak\t\t\t: "Įterpti puslapių skirtuką",\r\n
\r\n
Form\t\t\t: "Forma",\r\n
Checkbox\t\t: "Žymimasis langelis",\r\n
RadioButton\t\t: "Žymimoji akutė",\r\n
TextField\t\t: "Teksto laukas",\r\n
Textarea\t\t: "Teksto sritis",\r\n
HiddenField\t\t: "Nerodomas laukas",\r\n
Button\t\t\t: "Mygtukas",\r\n
SelectionField\t: "Atrankos laukas",\r\n
ImageButton\t\t: "Vaizdinis mygtukas",\r\n
\r\n
FitWindow\t\t: "Padidinti redaktorių",\r\n
ShowBlocks\t\t: "Rodyti blokus",\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Taisyti nuorodą",\r\n
CellCM\t\t\t\t: "Langelis",\r\n
RowCM\t\t\t\t: "Eilutė",\r\n
ColumnCM\t\t\t: "Stulpelis",\r\n
InsertRowAfter\t\t: "Įterpti eilutę po",\r\n
InsertRowBefore\t\t: "Įterpti eilutę prieš",\r\n
DeleteRows\t\t\t: "Šalinti eilutes",\r\n
InsertColumnAfter\t: "Įterpti stulpelį po",\r\n
InsertColumnBefore\t: "Įterpti stulpelį prieš",\r\n
DeleteColumns\t\t: "Šalinti stulpelius",\r\n
InsertCellAfter\t\t: "Įterpti langelį po",\r\n
InsertCellBefore\t: "Įterpti langelį prieš",\r\n
DeleteCells\t\t\t: "Šalinti langelius",\r\n
MergeCells\t\t\t: "Sujungti langelius",\r\n
MergeRight\t\t\t: "Sujungti su dešine",\r\n
MergeDown\t\t\t: "Sujungti su apačia",\r\n
HorizontalSplitCell\t: "Skaidyti langelį horizontaliai",\r\n
VerticalSplitCell\t: "Skaidyti langelį vertikaliai",\r\n
TableDelete\t\t\t: "Šalinti lentelę",\r\n
CellProperties\t\t: "Langelio savybės",\r\n
TableProperties\t\t: "Lentelės savybės",\r\n
ImageProperties\t\t: "Vaizdo savybės",\r\n
FlashProperties\t\t: "Flash savybės",\r\n
\r\n
AnchorProp\t\t\t: "Žymės savybės",\r\n
ButtonProp\t\t\t: "Mygtuko savybės",\r\n
CheckboxProp\t\t: "Žymimojo langelio savybės",\r\n
HiddenFieldProp\t\t: "Nerodomo lauko savybės",\r\n
RadioButtonProp\t\t: "Žymimosios akutės savybės",\r\n
ImageButtonProp\t\t: "Vaizdinio mygtuko savybės",\r\n
TextFieldProp\t\t: "Teksto lauko savybės",\r\n
SelectionFieldProp\t: "Atrankos lauko savybės",\r\n
TextareaProp\t\t: "Teksto srities savybės",\r\n
FormProp\t\t\t: "Formos savybės",\r\n
\r\n
FontFormats\t\t\t: "Normalus;Formuotas;Kreipinio;Antraštinis 1;Antraštinis 2;Antraštinis 3;Antraštinis 4;Antraštinis 5;Antraštinis 6",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "Apdorojamas XHTML. Prašome palaukti...",\r\n
Done\t\t\t\t: "Baigta",\r\n
PasteWordConfirm\t: "Įdedamas tekstas yra panašus į kopiją iš Word. Ar Jūs norite prieš įdėjimą išvalyti jį?",\r\n
NotCompatiblePaste\t: "Ši komanda yra prieinama tik per Internet Explorer 5.5 ar aukštesnę versiją. Ar Jūs norite įterpti be valymo?",\r\n
UnknownToolbarItem\t: "Nežinomas mygtukų juosta elementas \\"%1\\"",\r\n
UnknownCommand\t\t: "Nežinomas komandos vardas \\"%1\\"",\r\n
NotImplemented\t\t: "Komanda nėra įgyvendinta",\r\n
UnknownToolbarSet\t: "Mygtukų juostos rinkinys \\"%1\\" neegzistuoja",\r\n
NoActiveX\t\t\t: "Jūsų naršyklės saugumo nuostatos gali riboti kai kurias redaktoriaus savybes. Jūs turite aktyvuoti opciją \\"Run ActiveX controls and plug-ins\\". Kitu atveju Jums bus pranešama apie klaidas ir trūkstamas savybes.",\r\n
BrowseServerBlocked : "Neįmanoma atidaryti naujo naršyklės lango. Įsitikinkite, kad iškylančių langų blokavimo programos neveiksnios.",\r\n
DialogBlocked\t\t: "Neįmanoma atidaryti dialogo lango. Įsitikinkite, kad iškylančių langų blokavimo programos neveiksnios.",\r\n
VisitLinkBlocked\t: "Neįmanoma atidaryti naujo lango. Įsitikinkite, kad iškylančių langų blokavimo programos neveiksnios.",\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "OK",\r\n
DlgBtnCancel\t\t: "Nutraukti",\r\n
DlgBtnClose\t\t\t: "Uždaryti",\r\n
DlgBtnBrowseServer\t: "Naršyti po serverį",\r\n
DlgAdvancedTag\t\t: "Papildomas",\r\n
DlgOpOther\t\t\t: "<Kita>",\r\n
DlgInfoTab\t\t\t: "Informacija",\r\n
DlgAlertUrl\t\t\t: "Prašome įrašyti URL",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<nėra nustatyta>",\r\n
DlgGenId\t\t\t: "Id",\r\n
DlgGenLangDir\t\t: "Teksto kryptis",\r\n
DlgGenLangDirLtr\t: "Iš kairės į dešinę (LTR)",\r\n
DlgGenLangDirRtl\t: "Iš dešinės į kairę (RTL)",\r\n
DlgGenLangCode\t\t: "Kalbos kodas",\r\n
DlgGenAccessKey\t\t: "Prieigos raktas",\r\n
DlgGenName\t\t\t: "Vardas",\r\n
DlgGenTabIndex\t\t: "Tabuliavimo indeksas",\r\n
DlgGenLongDescr\t\t: "Ilgas aprašymas URL",\r\n
DlgGenClass\t\t\t: "Stilių lentelės klasės",\r\n
DlgGenTitle\t\t\t: "Konsultacinė antraštė",\r\n
DlgGenContType\t\t: "Konsultacinio turinio tipas",\r\n
DlgGenLinkCharset\t: "Susietų išteklių simbolių lentelė",\r\n
DlgGenStyle\t\t\t: "Stilius",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Vaizdo savybės",\r\n
DlgImgInfoTab\t\t: "Vaizdo informacija",\r\n
DlgImgBtnUpload\t\t: "Siųsti į serverį",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "Nusiųsti",\r\n
DlgImgAlt\t\t\t: "Alternatyvus Tekstas",\r\n
DlgImgWidth\t\t\t: "Plotis",\r\n
DlgImgHeight\t\t: "Aukštis",\r\n
DlgImgLockRatio\t\t: "Išlaikyti proporciją",\r\n
DlgBtnResetSize\t\t: "Atstatyti dydį",\r\n
DlgImgBorder\t\t: "Rėmelis",\r\n
DlgImgHSpace\t\t: "Hor.Erdvė",\r\n
DlgImgVSpace\t\t: "Vert.Erdvė",\r\n
DlgImgAlign\t\t\t: "Lygiuoti",\r\n
DlgImgAlignLeft\t\t: "Kairę",\r\n
DlgImgAlignAbsBottom: "Absoliučią apačią",\r\n
DlgImgAlignAbsMiddle: "Absoliutų vidurį",\r\n
DlgImgAlignBaseline\t: "Apatinę liniją",\r\n
DlgImgAlignBottom\t: "Apačią",\r\n
DlgImgAlignMiddle\t: "Vidurį",\r\n
DlgImgAlignRight\t: "Dešinę",\r\n
DlgImgAlignTextTop\t: "Teksto viršūnę",\r\n
DlgImgAlignTop\t\t: "Viršūnę",\r\n
DlgImgPreview\t\t: "Peržiūra",\r\n
DlgImgAlertUrl\t\t: "Prašome įvesti vaizdo URL",\r\n
DlgImgLinkTab\t\t: "Nuoroda",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Flash savybės",\r\n
DlgFlashChkPlay\t\t: "Automatinis paleidimas",\r\n
DlgFlashChkLoop\t\t: "Ciklas",\r\n
DlgFlashChkMenu\t\t: "Leisti Flash meniu",\r\n
DlgFlashScale\t\t: "Mastelis",\r\n
DlgFlashScaleAll\t: "Rodyti visą",\r\n
DlgFlashScaleNoBorder\t: "Be rėmelio",\r\n
DlgFlashScaleFit\t: "Tikslus atitikimas",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Nuoroda",\r\n
DlgLnkInfoTab\t\t: "Nuorodos informacija",\r\n
DlgLnkTargetTab\t\t: "Paskirtis",\r\n
\r\n
DlgLnkType\t\t\t: "Nuorodos tipas",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Žymė šiame puslapyje",\r\n
DlgLnkTypeEMail\t\t: "El.paštas",\r\n
DlgLnkProto\t\t\t: "Protokolas",\r\n
DlgLnkProtoOther\t: "<kitas>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Pasirinkite žymę",\r\n
DlgLnkAnchorByName\t: "Pagal žymės vardą",\r\n
DlgLnkAnchorById\t: "Pagal žymės Id",\r\n
DlgLnkNoAnchors\t\t: "(Šiame dokumente žymių nėra)",\r\n
DlgLnkEMail\t\t\t: "El.pašto adresas",\r\n
DlgLnkEMailSubject\t: "Žinutės tema",\r\n
DlgLnkEMailBody\t\t: "Žinutės turinys",\r\n
DlgLnkUpload\t\t: "Siųsti",\r\n
DlgLnkBtnUpload\t\t: "Siųsti į serverį",\r\n
\r\n
DlgLnkTarget\t\t: "Paskirties vieta",\r\n
DlgLnkTargetFrame\t: "<kadras>",\r\n
DlgLnkTargetPopup\t: "<išskleidžiamas langas>",\r\n
DlgLnkTargetBlank\t: "Naujas langas (_blank)",\r\n
DlgLnkTargetParent\t: "Pirminis langas (_parent)",\r\n
DlgLnkTargetSelf\t: "Tas pats langas (_self)",\r\n
DlgLnkTargetTop\t\t: "Svarbiausias langas (_top)",\r\n
DlgLnkTargetFrameName\t: "Paskirties kadro vardas",\r\n
DlgLnkPopWinName\t: "Paskirties lango vardas",\r\n
DlgLnkPopWinFeat\t: "Išskleidžiamo lango savybės",\r\n
DlgLnkPopResize\t\t: "Keičiamas dydis",\r\n
DlgLnkPopLocation\t: "Adreso juosta",\r\n
DlgLnkPopMenu\t\t: "Meniu juosta",\r\n
DlgLnkPopScroll\t\t: "Slinkties juostos",\r\n
DlgLnkPopStatus\t\t: "Būsenos juosta",\r\n
DlgLnkPopToolbar\t: "Mygtukų juosta",\r\n
DlgLnkPopFullScrn\t: "Visas ekranas (IE)",\r\n
DlgLnkPopDependent\t: "Priklausomas (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Plotis",\r\n
DlgLnkPopHeight\t\t: "Aukštis",\r\n
DlgLnkPopLeft\t\t: "Kairė pozicija",\r\n
DlgLnkPopTop\t\t: "Viršutinė pozicija",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Prašome įvesti nuorodos URL",\r\n
DlnLnkMsgNoEMail\t: "Prašome įvesti el.pašto adresą",\r\n
DlnLnkMsgNoAnchor\t: "Prašome pasirinkti žymę",\r\n
DlnLnkMsgInvPopName\t: "Iššokančio lango pavadinimas privalo prasidėti lotyniška raide ir negali turėti tarpų",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Pasirinkite spalvą",\r\n
DlgColorBtnClear\t: "Trinti",\r\n
DlgColorHighlight\t: "Paryškinta",\r\n
DlgColorSelected\t: "Pažymėta",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Įterpti veidelį",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Pasirinkite specialų simbolį",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Lentelės savybės",\r\n
DlgTableRows\t\t: "Eilutės",\r\n
DlgTableColumns\t\t: "Stulpeliai",\r\n
DlgTableBorder\t\t: "Rėmelio dydis",\r\n
DlgTableAlign\t\t: "Lygiuoti",\r\n
DlgTableAlignNotSet\t: "<Nenustatyta>",\r\n
DlgTableAlignLeft\t: "Kairę",\r\n
DlgTableAlignCenter\t: "Centrą",\r\n
DlgTableAlignRight\t: "Dešinę",\r\n
DlgTableWidth\t\t: "Plotis",\r\n
DlgTableWidthPx\t\t: "taškais",\r\n
DlgTableWidthPc\t\t: "procentais",\r\n
DlgTableHeight\t\t: "Aukštis",\r\n
DlgTableCellSpace\t: "Tarpas tarp langelių",\r\n
DlgTableCellPad\t\t: "Trapas nuo langelio rėmo iki teksto",\r\n
DlgTableCaption\t\t: "Antraštė",\r\n
DlgTableSummary\t\t: "Santrauka",\r\n
DlgTableHeaders\t\t: "Antraštės",\r\n
DlgTableHeadersNone\t\t: "Nėra",\r\n
DlgTableHeadersColumn\t: "Pirmas stulpelis",\r\n
DlgTableHeadersRow\t\t: "Pirma eilutė",\r\n
DlgTableHeadersBoth\t\t: "Abu",\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Langelio savybės",\r\n
DlgCellWidth\t\t: "Plotis",\r\n
DlgCellWidthPx\t\t: "taškais",\r\n
DlgCellWidthPc\t\t: "procentais",\r\n
DlgCellHeight\t\t: "Aukštis",\r\n
DlgCellWordWrap\t\t: "Teksto laužymas",\r\n
DlgCellWordWrapNotSet\t: "<Nenustatyta>",\r\n
DlgCellWordWrapYes\t: "Taip",\r\n
DlgCellWordWrapNo\t: "Ne",\r\n
DlgCellHorAlign\t\t: "Horizontaliai lygiuoti",\r\n
DlgCellHorAlignNotSet\t: "<Nenustatyta>",\r\n
DlgCellHorAlignLeft\t: "Kairę",\r\n
DlgCellHorAlignCenter\t: "Centrą",\r\n
DlgCellHorAlignRight: "Dešinę",\r\n
DlgCellVerAlign\t\t: "Vertikaliai lygiuoti",\r\n
DlgCellVerAlignNotSet\t: "<Nenustatyta>",\r\n
DlgCellVerAlignTop\t: "Viršų",\r\n
DlgCellVerAlignMiddle\t: "Vidurį",\r\n
DlgCellVerAlignBottom\t: "Apačią",\r\n
DlgCellVerAlignBaseline\t: "Apatinę liniją",\r\n
DlgCellType\t\t: "Langelio tipas",\r\n
DlgCellTypeData\t\t: "Duomenys",\r\n
DlgCellTypeHeader\t: "Antraštė",\r\n
DlgCellRowSpan\t\t: "Eilučių apjungimas",\r\n
DlgCellCollSpan\t\t: "Stulpelių apjungimas",\r\n
DlgCellBackColor\t: "Fono spalva",\r\n
DlgCellBorderColor\t: "Rėmelio spalva",\r\n
DlgCellBtnSelect\t: "Pažymėti...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Surasti ir pakeisti",\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Paieška",\r\n
DlgFindFindBtn\t\t: "Surasti",\r\n
DlgFindNotFoundMsg\t: "Nurodytas tekstas nerastas.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Pakeisti",\r\n
DlgReplaceFindLbl\t\t: "Surasti tekstą:",\r\n
DlgReplaceReplaceLbl\t: "Pakeisti tekstu:",\r\n
DlgReplaceCaseChk\t\t: "Skirti didžiąsias ir mažąsias raides",\r\n
DlgReplaceReplaceBtn\t: "Pakeisti",\r\n
DlgReplaceReplAllBtn\t: "Pakeisti viską",\r\n
DlgReplaceWordChk\t\t: "Atitikti pilną žodį",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "Jūsų naršyklės saugumo nustatymai neleidžia redaktoriui automatiškai įvykdyti iškirpimo operacijų. Tam prašome naudoti klaviatūrą (Ctrl+X).",\r\n
PasteErrorCopy\t: "Jūsų naršyklės saugumo nustatymai neleidžia redaktoriui automatiškai įvykdyti kopijavimo operacijų. Tam prašome naudoti klaviatūrą (Ctrl+C).",\r\n
\r\n
PasteAsText\t\t: "Įdėti kaip gryną tekstą",\r\n
PasteFromWord\t: "Įdėti iš Word",\r\n
\r\n
DlgPasteMsg2\t: "Žemiau esančiame įvedimo lauke įdėkite tekstą, naudodami klaviatūrą (<STRONG>Ctrl+V</STRONG>) ir paspauskite mygtuką <STRONG>OK</STRONG>.",\r\n
DlgPasteSec\t\t: "Dėl jūsų naršyklės saugumo nustatymų, redaktorius negali tiesiogiai pasiekti laikinosios atminties. Jums reikia nukopijuoti dar kartą į šį langą.",\r\n
DlgPasteIgnoreFont\t\t: "Ignoruoti šriftų nustatymus",\r\n
DlgPasteRemoveStyles\t: "Pašalinti stilių nustatymus",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Automatinis",\r\n
ColorMoreColors\t: "Daugiau spalvų...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Dokumento savybės",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Žymės savybės",\r\n
DlgAnchorName\t\t: "Žymės vardas",\r\n
DlgAnchorErrorName\t: "Prašome įvesti žymės vardą",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Žodyne nerastas",\r\n
DlgSpellChangeTo\t\t: "Pakeisti į",\r\n
DlgSpellBtnIgnore\t\t: "Ignoruoti",\r\n
DlgSpellBtnIgnoreAll\t: "Ignoruoti visus",\r\n
DlgSpellBtnReplace\t\t: "Pakeisti",\r\n
DlgSpellBtnReplaceAll\t: "Pakeisti visus",\r\n
DlgSpellBtnUndo\t\t\t: "Atšaukti",\r\n
DlgSpellNoSuggestions\t: "- Nėra pasiūlymų -",\r\n
DlgSpellProgress\t\t: "Vyksta rašybos tikrinimas...",\r\n
DlgSpellNoMispell\t\t: "Rašybos tikrinimas baigtas: Nerasta rašybos klaidų",\r\n
DlgSpellNoChanges\t\t: "Rašybos tikrinimas baigtas: Nėra pakeistų žodžių",\r\n
DlgSpellOneChange\t\t: "Rašybos tikrinimas baigtas: Vienas žodis pakeistas",\r\n
DlgSpellManyChanges\t\t: "Rašybos tikrinimas baigtas: Pakeista %1 žodžių",\r\n
\r\n
IeSpellDownload\t\t\t: "Rašybos tikrinimas neinstaliuotas. Ar Jūs norite jį dabar atsisiųsti?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Tekstas (Reikšmė)",\r\n
DlgButtonType\t\t: "Tipas",\r\n
DlgButtonTypeBtn\t: "Mygtukas",\r\n
DlgButtonTypeSbm\t: "Siųsti",\r\n
DlgButtonTypeRst\t: "Išvalyti",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Vardas",\r\n
DlgCheckboxValue\t: "Reikšmė",\r\n
DlgCheckboxSelected\t: "Pažymėtas",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Vardas",\r\n
DlgFormAction\t: "Veiksmas",\r\n
DlgFormMethod\t: "Metodas",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Vardas",\r\n
DlgSelectValue\t\t: "Reikšmė",\r\n
DlgSelectSize\t\t: "Dydis",\r\n
DlgSelectLines\t\t: "eilučių",\r\n
DlgSelectChkMulti\t: "Leisti daugeriopą atranką",\r\n
DlgSelectOpAvail\t: "Galimos parinktys",\r\n
DlgSelectOpText\t\t: "Tekstas",\r\n
DlgSelectOpValue\t: "Reikšmė",\r\n
DlgSelectBtnAdd\t\t: "Įtraukti",\r\n
DlgSelectBtnModify\t: "Modifikuoti",\r\n
DlgSelectBtnUp\t\t: "Aukštyn",\r\n
DlgSelectBtnDown\t: "Žemyn",\r\n
DlgSelectBtnSetValue : "Laikyti pažymėta reikšme",\r\n
DlgSelectBtnDelete\t: "Trinti",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Vardas",\r\n
DlgTextareaCols\t: "Ilgis",\r\n
DlgTextareaRows\t: "Plotis",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Vardas",\r\n
DlgTextValue\t\t: "Reikšmė",\r\n
DlgTextCharWidth\t: "Ilgis simboliais",\r\n
DlgTextMaxChars\t\t: "Maksimalus simbolių skaičius",\r\n
DlgTextType\t\t\t: "Tipas",\r\n
DlgTextTypeText\t\t: "Tekstas",\r\n
DlgTextTypePass\t\t: "Slaptažodis",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Vardas",\r\n
DlgHiddenValue\t: "Reikšmė",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Suženklinto sąrašo savybės",\r\n
NumberedListProp\t: "Numeruoto sąrašo savybės",\r\n
DlgLstStart\t\t\t: "Pradėti nuo",\r\n
DlgLstType\t\t\t: "Tipas",\r\n
DlgLstTypeCircle\t: "Apskritimas",\r\n
DlgLstTypeDisc\t\t: "Diskas",\r\n
DlgLstTypeSquare\t: "Kvadratas",\r\n
DlgLstTypeNumbers\t: "Skaičiai (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Mažosios raidės (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Didžiosios raidės (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Romėnų mažieji skaičiai (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Romėnų didieji skaičiai (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Bendros savybės",\r\n
DlgDocBackTab\t\t: "Fonas",\r\n
DlgDocColorsTab\t\t: "Spalvos ir kraštinės",\r\n
DlgDocMetaTab\t\t: "Meta duomenys",\r\n
\r\n
DlgDocPageTitle\t\t: "Puslapio antraštė",\r\n
DlgDocLangDir\t\t: "Kalbos kryptis",\r\n
DlgDocLangDirLTR\t: "Iš kairės į dešinę (LTR)",\r\n
DlgDocLangDirRTL\t: "Iš dešinės į kairę (RTL)",\r\n
DlgDocLangCode\t\t: "Kalbos kodas",\r\n
DlgDocCharSet\t\t: "Simbolių kodavimo lentelė",\r\n
DlgDocCharSetCE\t\t: "Centrinės Europos",\r\n
DlgDocCharSetCT\t\t: "Tradicinės kinų (Big5)",\r\n
DlgDocCharSetCR\t\t: "Kirilica",\r\n
DlgDocCharSetGR\t\t: "Graikų",\r\n
DlgDocCharSetJP\t\t: "Japonų",\r\n
DlgDocCharSetKR\t\t: "Korėjiečių",\r\n
DlgDocCharSetTR\t\t: "Turkų",\r\n
DlgDocCharSetUN\t\t: "Unikodas (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "Vakarų Europos",\r\n
DlgDocCharSetOther\t: "Kita simbolių kodavimo lentelė",\r\n
\r\n
DlgDocDocType\t\t: "Dokumento tipo antraštė",\r\n
DlgDocDocTypeOther\t: "Kita dokumento tipo antraštė",\r\n
DlgDocIncXHTML\t\t: "Įtraukti XHTML deklaracijas",\r\n
DlgDocBgColor\t\t: "Fono spalva",\r\n
DlgDocBgImage\t\t: "Fono paveikslėlio nuoroda (URL)",\r\n
DlgDocBgNoScroll\t: "Neslenkantis fonas",\r\n
DlgDocCText\t\t\t: "Tekstas",\r\n
DlgDocCLink\t\t\t: "Nuoroda",\r\n
DlgDocCVisited\t\t: "Aplankyta nuoroda",\r\n
DlgDocCActive\t\t: "Aktyvi nuoroda",\r\n
DlgDocMargins\t\t: "Puslapio kraštinės",\r\n
DlgDocMaTop\t\t\t: "Viršuje",\r\n
DlgDocMaLeft\t\t: "Kairėje",\r\n
DlgDocMaRight\t\t: "Dešinėje",\r\n
DlgDocMaBottom\t\t: "Apačioje",\r\n
DlgDocMeIndex\t\t: "Dokumento indeksavimo raktiniai žodžiai (atskirti kableliais)",\r\n
DlgDocMeDescr\t\t: "Dokumento apibūdinimas",\r\n
DlgDocMeAuthor\t\t: "Autorius",\r\n
DlgDocMeCopy\t\t: "Autorinės teisės",\r\n
DlgDocPreview\t\t: "Peržiūra",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Šablonai",\r\n
DlgTemplatesTitle\t: "Turinio šablonai",\r\n
DlgTemplatesSelMsg\t: "Pasirinkite norimą šabloną<br>(<b>Dėmesio!</b> esamas turinys bus prarastas):",\r\n
DlgTemplatesLoading\t: "Įkeliamas šablonų sąrašas. Prašome palaukti...",\r\n
DlgTemplatesNoTpl\t: "(Šablonų sąrašas tuščias)",\r\n
DlgTemplatesReplace\t: "Pakeisti dabartinį turinį pasirinktu šablonu",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Apie",\r\n
DlgAboutBrowserInfoTab\t: "Naršyklės informacija",\r\n
DlgAboutLicenseTab\t: "Licenzija",\r\n
DlgAboutVersion\t\t: "versija",\r\n
DlgAboutInfo\t\t: "Papildomą informaciją galima gauti",\r\n
\r\n
// Div Dialog\r\n
DlgDivGeneralTab\t: "Bendros savybės",\r\n
DlgDivAdvancedTab\t: "Papildomos savybės",\r\n
DlgDivStyle\t\t: "Stilius",\r\n
DlgDivInlineStyle\t: "Stilius kode",\r\n
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
            <value> <int>19915</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
