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
            <value> <string>sr.js</string> </value>
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
 * Serbian (Cyrillic) language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Смањи линију са алаткама",\r\n
ToolbarExpand\t\t: "Прошири линију са алаткама",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Сачувај",\r\n
NewPage\t\t\t\t: "Нова страница",\r\n
Preview\t\t\t\t: "Изглед странице",\r\n
Cut\t\t\t\t\t: "Исеци",\r\n
Copy\t\t\t\t: "Копирај",\r\n
Paste\t\t\t\t: "Залепи",\r\n
PasteText\t\t\t: "Залепи као неформатиран текст",\r\n
PasteWord\t\t\t: "Залепи из Worda",\r\n
Print\t\t\t\t: "Штампа",\r\n
SelectAll\t\t\t: "Означи све",\r\n
RemoveFormat\t\t: "Уклони форматирање",\r\n
InsertLinkLbl\t\t: "Линк",\r\n
InsertLink\t\t\t: "Унеси/измени линк",\r\n
RemoveLink\t\t\t: "Уклони линк",\r\n
VisitLink\t\t\t: "Open Link",\t//MISSING\r\n
Anchor\t\t\t\t: "Унеси/измени сидро",\r\n
AnchorDelete\t\t: "Remove Anchor",\t//MISSING\r\n
InsertImageLbl\t\t: "Слика",\r\n
InsertImage\t\t\t: "Унеси/измени слику",\r\n
InsertFlashLbl\t\t: "Флеш елемент",\r\n
InsertFlash\t\t\t: "Унеси/измени флеш",\r\n
InsertTableLbl\t\t: "Табела",\r\n
InsertTable\t\t\t: "Унеси/измени табелу",\r\n
InsertLineLbl\t\t: "Линија",\r\n
InsertLine\t\t\t: "Унеси хоризонталну линију",\r\n
InsertSpecialCharLbl: "Специјални карактери",\r\n
InsertSpecialChar\t: "Унеси специјални карактер",\r\n
InsertSmileyLbl\t\t: "Смајли",\r\n
InsertSmiley\t\t: "Унеси смајлија",\r\n
About\t\t\t\t: "О ФЦКедитору",\r\n
Bold\t\t\t\t: "Подебљано",\r\n
Italic\t\t\t\t: "Курзив",\r\n
Underline\t\t\t: "Подвучено",\r\n
StrikeThrough\t\t: "Прецртано",\r\n
Subscript\t\t\t: "Индекс",\r\n
Superscript\t\t\t: "Степен",\r\n
LeftJustify\t\t\t: "Лево равнање",\r\n
CenterJustify\t\t: "Центриран текст",\r\n
RightJustify\t\t: "Десно равнање",\r\n
BlockJustify\t\t: "Обострано равнање",\r\n
DecreaseIndent\t\t: "Смањи леву маргину",\r\n
IncreaseIndent\t\t: "Увећај леву маргину",\r\n
Blockquote\t\t\t: "Blockquote",\t//MISSING\r\n
CreateDiv\t\t\t: "Create Div Container",\t//MISSING\r\n
EditDiv\t\t\t\t: "Edit Div Container",\t//MISSING\r\n
DeleteDiv\t\t\t: "Remove Div Container",\t//MISSING\r\n
Undo\t\t\t\t: "Поништи акцију",\r\n
Redo\t\t\t\t: "Понови акцију",\r\n
NumberedListLbl\t\t: "Набројиву листу",\r\n
NumberedList\t\t: "Унеси/уклони набројиву листу",\r\n
BulletedListLbl\t\t: "Ненабројива листа",\r\n
BulletedList\t\t: "Унеси/уклони ненабројиву листу",\r\n
ShowTableBorders\t: "Прикажи оквир табеле",\r\n
ShowDetails\t\t\t: "Прикажи детаље",\r\n
Style\t\t\t\t: "Стил",\r\n
FontFormat\t\t\t: "Формат",\r\n
Font\t\t\t\t: "Фонт",\r\n
FontSize\t\t\t: "Величина фонта",\r\n
TextColor\t\t\t: "Боја текста",\r\n
BGColor\t\t\t\t: "Боја позадине",\r\n
Source\t\t\t\t: "Kôд",\r\n
Find\t\t\t\t: "Претрага",\r\n
Replace\t\t\t\t: "Замена",\r\n
SpellCheck\t\t\t: "Провери спеловање",\r\n
UniversalKeyboard\t: "Универзална тастатура",\r\n
PageBreakLbl\t\t: "Page Break",\t//MISSING\r\n
PageBreak\t\t\t: "Insert Page Break",\t//MISSING\r\n
\r\n
Form\t\t\t: "Форма",\r\n
Checkbox\t\t: "Поље за потврду",\r\n
RadioButton\t\t: "Радио-дугме",\r\n
TextField\t\t: "Текстуално поље",\r\n
Textarea\t\t: "Зона текста",\r\n
HiddenField\t\t: "Скривено поље",\r\n
Button\t\t\t: "Дугме",\r\n
SelectionField\t: "Изборно поље",\r\n
ImageButton\t\t: "Дугме са сликом",\r\n
\r\n
FitWindow\t\t: "Maximize the editor size",\t//MISSING\r\n
ShowBlocks\t\t: "Show Blocks",\t//MISSING\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Промени линк",\r\n
CellCM\t\t\t\t: "Cell",\t//MISSING\r\n
RowCM\t\t\t\t: "Row",\t//MISSING\r\n
ColumnCM\t\t\t: "Column",\t//MISSING\r\n
InsertRowAfter\t\t: "Insert Row After",\t//MISSING\r\n
InsertRowBefore\t\t: "Insert Row Before",\t//MISSING\r\n
DeleteRows\t\t\t: "Обриши редове",\r\n
InsertColumnAfter\t: "Insert Column After",\t//MISSING\r\n
InsertColumnBefore\t: "Insert Column Before",\t//MISSING\r\n
DeleteColumns\t\t: "Обриши колоне",\r\n
InsertCellAfter\t\t: "Insert Cell After",\t//MISSING\r\n
InsertCellBefore\t: "Insert Cell Before",\t//MISSING\r\n
DeleteCells\t\t\t: "Обриши ћелије",\r\n
MergeCells\t\t\t: "Спој ћелије",\r\n
MergeRight\t\t\t: "Merge Right",\t//MISSING\r\n
MergeDown\t\t\t: "Merge Down",\t//MISSING\r\n
HorizontalSplitCell\t: "Split Cell Horizontally",\t//MISSING\r\n
VerticalSplitCell\t: "Split Cell Vertically",\t//MISSING\r\n
TableDelete\t\t\t: "Delete Table",\t//MISSING\r\n
CellProperties\t\t: "Особине ћелије",\r\n
TableProperties\t\t: "Особине табеле",\r\n
ImageProperties\t\t: "Особине слике",\r\n
FlashProperties\t\t: "Особине Флеша",\r\n
\r\n
AnchorProp\t\t\t: "Особине сидра",\r\n
ButtonProp\t\t\t: "Особине дугмета",\r\n
CheckboxProp\t\t: "Особине поља за потврду",\r\n
HiddenFieldProp\t\t: "Особине скривеног поља",\r\n
RadioButtonProp\t\t: "Особине радио-дугмета",\r\n
ImageButtonProp\t\t: "Особине дугмета са сликом",\r\n
TextFieldProp\t\t: "Особине текстуалног поља",\r\n
SelectionFieldProp\t: "Особине изборног поља",\r\n
TextareaProp\t\t: "Особине зоне текста",\r\n
FormProp\t\t\t: "Особине форме",\r\n
\r\n
FontFormats\t\t\t: "Normal;Formatirano;Adresa;Heading 1;Heading 2;Heading 3;Heading 4;Heading 5;Heading 6",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "Обрађујем XHTML. Maлo стрпљења...",\r\n
Done\t\t\t\t: "Завршио",\r\n
PasteWordConfirm\t: "Текст који желите да налепите копиран је из Worda. Да ли желите да буде очишћен од формата пре лепљења?",\r\n
NotCompatiblePaste\t: "Ова команда је доступна само за Интернет Екплорер од верзије 5.5. Да ли желите да налепим текст без чишћења?",\r\n
UnknownToolbarItem\t: "Непозната ставка toolbara \\"%1\\"",\r\n
UnknownCommand\t\t: "Непозната наредба \\"%1\\"",\r\n
NotImplemented\t\t: "Наредба није имплементирана",\r\n
UnknownToolbarSet\t: "Toolbar \\"%1\\" не постоји",\r\n
NoActiveX\t\t\t: "Your browser\'s security settings could limit some features of the editor. You must enable the option \\"Run ActiveX controls and plug-ins\\". You may experience errors and notice missing features.",\t//MISSING\r\n
BrowseServerBlocked : "The resources browser could not be opened. Make sure that all popup blockers are disabled.",\t//MISSING\r\n
DialogBlocked\t\t: "It was not possible to open the dialog window. Make sure all popup blockers are disabled.",\t//MISSING\r\n
VisitLinkBlocked\t: "It was not possible to open a new window. Make sure all popup blockers are disabled.",\t//MISSING\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "OK",\r\n
DlgBtnCancel\t\t: "Oткажи",\r\n
DlgBtnClose\t\t\t: "Затвори",\r\n
DlgBtnBrowseServer\t: "Претражи сервер",\r\n
DlgAdvancedTag\t\t: "Напредни тагови",\r\n
DlgOpOther\t\t\t: "<Остали>",\r\n
DlgInfoTab\t\t\t: "Инфо",\r\n
DlgAlertUrl\t\t\t: "Молимо Вас, унесите УРЛ",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<није постављено>",\r\n
DlgGenId\t\t\t: "Ид",\r\n
DlgGenLangDir\t\t: "Смер језика",\r\n
DlgGenLangDirLtr\t: "С лева на десно (LTR)",\r\n
DlgGenLangDirRtl\t: "С десна на лево (RTL)",\r\n
DlgGenLangCode\t\t: "Kôд језика",\r\n
DlgGenAccessKey\t\t: "Приступни тастер",\r\n
DlgGenName\t\t\t: "Назив",\r\n
DlgGenTabIndex\t\t: "Таб индекс",\r\n
DlgGenLongDescr\t\t: "Пун опис УРЛ",\r\n
DlgGenClass\t\t\t: "Stylesheet класе",\r\n
DlgGenTitle\t\t\t: "Advisory наслов",\r\n
DlgGenContType\t\t: "Advisory врста садржаја",\r\n
DlgGenLinkCharset\t: "Linked Resource Charset",\r\n
DlgGenStyle\t\t\t: "Стил",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Особине слика",\r\n
DlgImgInfoTab\t\t: "Инфо слике",\r\n
DlgImgBtnUpload\t\t: "Пошаљи на сервер",\r\n
DlgImgURL\t\t\t: "УРЛ",\r\n
DlgImgUpload\t\t: "Пошаљи",\r\n
DlgImgAlt\t\t\t: "Алтернативни текст",\r\n
DlgImgWidth\t\t\t: "Ширина",\r\n
DlgImgHeight\t\t: "Висина",\r\n
DlgImgLockRatio\t\t: "Закључај однос",\r\n
DlgBtnResetSize\t\t: "Ресетуј величину",\r\n
DlgImgBorder\t\t: "Оквир",\r\n
DlgImgHSpace\t\t: "HSpace",\r\n
DlgImgVSpace\t\t: "VSpace",\r\n
DlgImgAlign\t\t\t: "Равнање",\r\n
DlgImgAlignLeft\t\t: "Лево",\r\n
DlgImgAlignAbsBottom: "Abs доле",\r\n
DlgImgAlignAbsMiddle: "Abs средина",\r\n
DlgImgAlignBaseline\t: "Базно",\r\n
DlgImgAlignBottom\t: "Доле",\r\n
DlgImgAlignMiddle\t: "Средина",\r\n
DlgImgAlignRight\t: "Десно",\r\n
DlgImgAlignTextTop\t: "Врх текста",\r\n
DlgImgAlignTop\t\t: "Врх",\r\n
DlgImgPreview\t\t: "Изглед",\r\n
DlgImgAlertUrl\t\t: "Унесите УРЛ слике",\r\n
DlgImgLinkTab\t\t: "Линк",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Особине флеша",\r\n
DlgFlashChkPlay\t\t: "Аутоматски старт",\r\n
DlgFlashChkLoop\t\t: "Понављај",\r\n
DlgFlashChkMenu\t\t: "Укључи флеш мени",\r\n
DlgFlashScale\t\t: "Скалирај",\r\n
DlgFlashScaleAll\t: "Прикажи све",\r\n
DlgFlashScaleNoBorder\t: "Без ивице",\r\n
DlgFlashScaleFit\t: "Попуни површину",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Линк",\r\n
DlgLnkInfoTab\t\t: "Линк инфо",\r\n
DlgLnkTargetTab\t\t: "Мета",\r\n
\r\n
DlgLnkType\t\t\t: "Врста линка",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Сидро на овој страници",\r\n
DlgLnkTypeEMail\t\t: "Eлектронска пошта",\r\n
DlgLnkProto\t\t\t: "Протокол",\r\n
DlgLnkProtoOther\t: "<друго>",\r\n
DlgLnkURL\t\t\t: "УРЛ",\r\n
DlgLnkAnchorSel\t\t: "Одабери сидро",\r\n
DlgLnkAnchorByName\t: "По називу сидра",\r\n
DlgLnkAnchorById\t: "Пo Ид-jу елемента",\r\n
DlgLnkNoAnchors\t\t: "(Нема доступних сидра)",\r\n
DlgLnkEMail\t\t\t: "Адреса електронске поште",\r\n
DlgLnkEMailSubject\t: "Наслов",\r\n
DlgLnkEMailBody\t\t: "Садржај поруке",\r\n
DlgLnkUpload\t\t: "Пошаљи",\r\n
DlgLnkBtnUpload\t\t: "Пошаљи на сервер",\r\n
\r\n
DlgLnkTarget\t\t: "Meтa",\r\n
DlgLnkTargetFrame\t: "<оквир>",\r\n
DlgLnkTargetPopup\t: "<искачући прозор>",\r\n
DlgLnkTargetBlank\t: "Нови прозор (_blank)",\r\n
DlgLnkTargetParent\t: "Родитељски прозор (_parent)",\r\n
DlgLnkTargetSelf\t: "Исти прозор (_self)",\r\n
DlgLnkTargetTop\t\t: "Прозор на врху (_top)",\r\n
DlgLnkTargetFrameName\t: "Назив одредишног фрејма",\r\n
DlgLnkPopWinName\t: "Назив искачућег прозора",\r\n
DlgLnkPopWinFeat\t: "Могућности искачућег прозора",\r\n
DlgLnkPopResize\t\t: "Променљива величина",\r\n
DlgLnkPopLocation\t: "Локација",\r\n
DlgLnkPopMenu\t\t: "Контекстни мени",\r\n
DlgLnkPopScroll\t\t: "Скрол бар",\r\n
DlgLnkPopStatus\t\t: "Статусна линија",\r\n
DlgLnkPopToolbar\t: "Toolbar",\r\n
DlgLnkPopFullScrn\t: "Приказ преко целог екрана (ИE)",\r\n
DlgLnkPopDependent\t: "Зависно (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Ширина",\r\n
DlgLnkPopHeight\t\t: "Висина",\r\n
DlgLnkPopLeft\t\t: "Од леве ивице екрана (пиксела)",\r\n
DlgLnkPopTop\t\t: "Од врха екрана (пиксела)",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Унесите УРЛ линка",\r\n
DlnLnkMsgNoEMail\t: "Откуцајте адресу електронске поште",\r\n
DlnLnkMsgNoAnchor\t: "Одаберите сидро",\r\n
DlnLnkMsgInvPopName\t: "The popup name must begin with an alphabetic character and must not contain spaces",\t//MISSING\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Одаберите боју",\r\n
DlgColorBtnClear\t: "Обриши",\r\n
DlgColorHighlight\t: "Посветли",\r\n
DlgColorSelected\t: "Одабери",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Унеси смајлија",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Одаберите специјални карактер",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Особине табеле",\r\n
DlgTableRows\t\t: "Редова",\r\n
DlgTableColumns\t\t: "Kолона",\r\n
DlgTableBorder\t\t: "Величина оквира",\r\n
DlgTableAlign\t\t: "Равнање",\r\n
DlgTableAlignNotSet\t: "<није постављено>",\r\n
DlgTableAlignLeft\t: "Лево",\r\n
DlgTableAlignCenter\t: "Средина",\r\n
DlgTableAlignRight\t: "Десно",\r\n
DlgTableWidth\t\t: "Ширина",\r\n
DlgTableWidthPx\t\t: "пиксела",\r\n
DlgTableWidthPc\t\t: "процената",\r\n
DlgTableHeight\t\t: "Висина",\r\n
DlgTableCellSpace\t: "Ћелијски простор",\r\n
DlgTableCellPad\t\t: "Размак ћелија",\r\n
DlgTableCaption\t\t: "Наслов табеле",\r\n
DlgTableSummary\t\t: "Summary",\t//MISSING\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Особине ћелије",\r\n
DlgCellWidth\t\t: "Ширина",\r\n
DlgCellWidthPx\t\t: "пиксела",\r\n
DlgCellWidthPc\t\t: "процената",\r\n
DlgCellHeight\t\t: "Висина",\r\n
DlgCellWordWrap\t\t: "Дељење речи",\r\n
DlgCellWordWrapNotSet\t: "<није постављено>",\r\n
DlgCellWordWrapYes\t: "Да",\r\n
DlgCellWordWrapNo\t: "Не",\r\n
DlgCellHorAlign\t\t: "Водоравно равнање",\r\n
DlgCellHorAlignNotSet\t: "<није постављено>",\r\n
DlgCellHorAlignLeft\t: "Лево",\r\n
DlgCellHorAlignCenter\t: "Средина",\r\n
DlgCellHorAlignRight: "Десно",\r\n
DlgCellVerAlign\t\t: "Вертикално равнање",\r\n
DlgCellVerAlignNotSet\t: "<није постављено>",\r\n
DlgCellVerAlignTop\t: "Горње",\r\n
DlgCellVerAlignMiddle\t: "Средина",\r\n
DlgCellVerAlignBottom\t: "Доње",\r\n
DlgCellVerAlignBaseline\t: "Базно",\r\n
DlgCellType\t\t: "Cell Type",\t//MISSING\r\n
DlgCellTypeData\t\t: "Data",\t//MISSING\r\n
DlgCellTypeHeader\t: "Header",\t//MISSING\r\n
DlgCellRowSpan\t\t: "Спајање редова",\r\n
DlgCellCollSpan\t\t: "Спајање колона",\r\n
DlgCellBackColor\t: "Боја позадине",\r\n
DlgCellBorderColor\t: "Боја оквира",\r\n
DlgCellBtnSelect\t: "Oдабери...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Find and Replace",\t//MISSING\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Пронађи",\r\n
DlgFindFindBtn\t\t: "Пронађи",\r\n
DlgFindNotFoundMsg\t: "Тражени текст није пронађен.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Замени",\r\n
DlgReplaceFindLbl\t\t: "Пронађи:",\r\n
DlgReplaceReplaceLbl\t: "Замени са:",\r\n
DlgReplaceCaseChk\t\t: "Разликуј велика и мала слова",\r\n
DlgReplaceReplaceBtn\t: "Замени",\r\n
DlgReplaceReplAllBtn\t: "Замени све",\r\n
DlgReplaceWordChk\t\t: "Упореди целе речи",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "Сигурносна подешавања Вашег претраживача не дозвољавају операције аутоматског исецања текста. Молимо Вас да користите пречицу са тастатуре (Ctrl+X).",\r\n
PasteErrorCopy\t: "Сигурносна подешавања Вашег претраживача не дозвољавају операције аутоматског копирања текста. Молимо Вас да користите пречицу са тастатуре (Ctrl+C).",\r\n
\r\n
PasteAsText\t\t: "Залепи као чист текст",\r\n
PasteFromWord\t: "Залепи из Worda",\r\n
\r\n
DlgPasteMsg2\t: "Молимо Вас да залепите унутар доње површине користећи тастатурну пречицу (<STRONG>Ctrl+V</STRONG>) и да притиснете <STRONG>OK</STRONG>.",\r\n
DlgPasteSec\t\t: "Because of your browser security settings, the editor is not able to access your clipboard data directly. You are required to paste it again in this window.",\t//MISSING\r\n
DlgPasteIgnoreFont\t\t: "Игнориши Font Face дефиниције",\r\n
DlgPasteRemoveStyles\t: "Уклони дефиниције стилова",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Аутоматски",\r\n
ColorMoreColors\t: "Више боја...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Особине документа",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Особине сидра",\r\n
DlgAnchorName\t\t: "Име сидра",\r\n
DlgAnchorErrorName\t: "Молимо Вас да унесете име сидра",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Није у речнику",\r\n
DlgSpellChangeTo\t\t: "Измени",\r\n
DlgSpellBtnIgnore\t\t: "Игнориши",\r\n
DlgSpellBtnIgnoreAll\t: "Игнориши све",\r\n
DlgSpellBtnReplace\t\t: "Замени",\r\n
DlgSpellBtnReplaceAll\t: "Замени све",\r\n
DlgSpellBtnUndo\t\t\t: "Врати акцију",\r\n
DlgSpellNoSuggestions\t: "- Без сугестија -",\r\n
DlgSpellProgress\t\t: "Провера спеловања у току...",\r\n
DlgSpellNoMispell\t\t: "Провера спеловања завршена: грешке нису пронађене",\r\n
DlgSpellNoChanges\t\t: "Провера спеловања завршена: Није измењена ниједна реч",\r\n
DlgSpellOneChange\t\t: "Провера спеловања завршена: Измењена је једна реч",\r\n
DlgSpellManyChanges\t\t: "Провера спеловања завршена:  %1 реч(и) је измењено",\r\n
\r\n
IeSpellDownload\t\t\t: "Провера спеловања није инсталирана. Да ли желите да је скинете са Интернета?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Текст (вредност)",\r\n
DlgButtonType\t\t: "Tип",\r\n
DlgButtonTypeBtn\t: "Button",\t//MISSING\r\n
DlgButtonTypeSbm\t: "Submit",\t//MISSING\r\n
DlgButtonTypeRst\t: "Reset",\t//MISSING\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Назив",\r\n
DlgCheckboxValue\t: "Вредност",\r\n
DlgCheckboxSelected\t: "Означено",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Назив",\r\n
DlgFormAction\t: "Aкција",\r\n
DlgFormMethod\t: "Mетода",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Назив",\r\n
DlgSelectValue\t\t: "Вредност",\r\n
DlgSelectSize\t\t: "Величина",\r\n
DlgSelectLines\t\t: "линија",\r\n
DlgSelectChkMulti\t: "Дозволи вишеструку селекцију",\r\n
DlgSelectOpAvail\t: "Доступне опције",\r\n
DlgSelectOpText\t\t: "Текст",\r\n
DlgSelectOpValue\t: "Вредност",\r\n
DlgSelectBtnAdd\t\t: "Додај",\r\n
DlgSelectBtnModify\t: "Измени",\r\n
DlgSelectBtnUp\t\t: "Горе",\r\n
DlgSelectBtnDown\t: "Доле",\r\n
DlgSelectBtnSetValue : "Подеси као означену вредност",\r\n
DlgSelectBtnDelete\t: "Обриши",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Назив",\r\n
DlgTextareaCols\t: "Број колона",\r\n
DlgTextareaRows\t: "Број редова",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Назив",\r\n
DlgTextValue\t\t: "Вредност",\r\n
DlgTextCharWidth\t: "Ширина (карактера)",\r\n
DlgTextMaxChars\t\t: "Максимално карактера",\r\n
DlgTextType\t\t\t: "Тип",\r\n
DlgTextTypeText\t\t: "Текст",\r\n
DlgTextTypePass\t\t: "Лозинка",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Назив",\r\n
DlgHiddenValue\t: "Вредност",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Особине Bulleted листе",\r\n
NumberedListProp\t: "Особине набројиве листе",\r\n
DlgLstStart\t\t\t: "Start",\t//MISSING\r\n
DlgLstType\t\t\t: "Тип",\r\n
DlgLstTypeCircle\t: "Круг",\r\n
DlgLstTypeDisc\t\t: "Disc",\t//MISSING\r\n
DlgLstTypeSquare\t: "Квадрат",\r\n
DlgLstTypeNumbers\t: "Бројеви (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "мала слова (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "ВЕЛИКА СЛОВА (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Мале римске цифре (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Велике римске цифре (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Опште особине",\r\n
DlgDocBackTab\t\t: "Позадина",\r\n
DlgDocColorsTab\t\t: "Боје и маргине",\r\n
DlgDocMetaTab\t\t: "Метаподаци",\r\n
\r\n
DlgDocPageTitle\t\t: "Наслов странице",\r\n
DlgDocLangDir\t\t: "Смер језика",\r\n
DlgDocLangDirLTR\t: "Слева надесно (LTR)",\r\n
DlgDocLangDirRTL\t: "Здесна налево (RTL)",\r\n
DlgDocLangCode\t\t: "Шифра језика",\r\n
DlgDocCharSet\t\t: "Кодирање скупа карактера",\r\n
DlgDocCharSetCE\t\t: "Central European",\t//MISSING\r\n
DlgDocCharSetCT\t\t: "Chinese Traditional (Big5)",\t//MISSING\r\n
DlgDocCharSetCR\t\t: "Cyrillic",\t//MISSING\r\n
DlgDocCharSetGR\t\t: "Greek",\t//MISSING\r\n
DlgDocCharSetJP\t\t: "Japanese",\t//MISSING\r\n
DlgDocCharSetKR\t\t: "Korean",\t//MISSING\r\n
DlgDocCharSetTR\t\t: "Turkish",\t//MISSING\r\n
DlgDocCharSetUN\t\t: "Unicode (UTF-8)",\t//MISSING\r\n
DlgDocCharSetWE\t\t: "Western European",\t//MISSING\r\n
DlgDocCharSetOther\t: "Остала кодирања скупа карактера",\r\n
\r\n
DlgDocDocType\t\t: "Заглавље типа документа",\r\n
DlgDocDocTypeOther\t: "Остала заглавља типа документа",\r\n
DlgDocIncXHTML\t\t: "Улључи XHTML декларације",\r\n
DlgDocBgColor\t\t: "Боја позадине",\r\n
DlgDocBgImage\t\t: "УРЛ позадинске слике",\r\n
DlgDocBgNoScroll\t: "Фиксирана позадина",\r\n
DlgDocCText\t\t\t: "Текст",\r\n
DlgDocCLink\t\t\t: "Линк",\r\n
DlgDocCVisited\t\t: "Посећени линк",\r\n
DlgDocCActive\t\t: "Активни линк",\r\n
DlgDocMargins\t\t: "Маргине странице",\r\n
DlgDocMaTop\t\t\t: "Горња",\r\n
DlgDocMaLeft\t\t: "Лева",\r\n
DlgDocMaRight\t\t: "Десна",\r\n
DlgDocMaBottom\t\t: "Доња",\r\n
DlgDocMeIndex\t\t: "Кључне речи за индексирање документа (раздвојене зарезом)",\r\n
DlgDocMeDescr\t\t: "Опис документа",\r\n
DlgDocMeAuthor\t\t: "Аутор",\r\n
DlgDocMeCopy\t\t: "Ауторска права",\r\n
DlgDocPreview\t\t: "Изглед странице",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Обрасци",\r\n
DlgTemplatesTitle\t: "Обрасци за садржај",\r\n
DlgTemplatesSelMsg\t: "Молимо Вас да одаберете образац који ће бити примењен на страницу (тренутни садржај ће бити обрисан):",\r\n
DlgTemplatesLoading\t: "Учитавам листу образаца. Мало стрпљења...",\r\n
DlgTemplatesNoTpl\t: "(Нема дефинисаних образаца)",\r\n
DlgTemplatesReplace\t: "Replace actual contents",\t//MISSING\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "О едитору",\r\n
DlgAboutBrowserInfoTab\t: "Информације о претраживачу",\r\n
DlgAboutLicenseTab\t: "License",\t//MISSING\r\n
DlgAboutVersion\t\t: "верзија",\r\n
DlgAboutInfo\t\t: "За више информација посетите",\r\n
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
            <value> <int>23934</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
