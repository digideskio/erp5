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
            <value> <string>mn.js</string> </value>
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
 * Mongolian language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Багажны хэсэг эвдэх",\r\n
ToolbarExpand\t\t: "Багажны хэсэг өргөтгөх",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Хадгалах",\r\n
NewPage\t\t\t\t: "Шинэ хуудас",\r\n
Preview\t\t\t\t: "Уридчлан харах",\r\n
Cut\t\t\t\t\t: "Хайчлах",\r\n
Copy\t\t\t\t: "Хуулах",\r\n
Paste\t\t\t\t: "Буулгах",\r\n
PasteText\t\t\t: "plain text-ээс буулгах",\r\n
PasteWord\t\t\t: "Word-оос буулгах",\r\n
Print\t\t\t\t: "Хэвлэх",\r\n
SelectAll\t\t\t: "Бүгдийг нь сонгох",\r\n
RemoveFormat\t\t: "Формат авч хаях",\r\n
InsertLinkLbl\t\t: "Линк",\r\n
InsertLink\t\t\t: "Линк Оруулах/Засварлах",\r\n
RemoveLink\t\t\t: "Линк авч хаях",\r\n
VisitLink\t\t\t: "Open Link",\t//MISSING\r\n
Anchor\t\t\t\t: "Холбоос Оруулах/Засварлах",\r\n
AnchorDelete\t\t: "Холбоос Авах",\r\n
InsertImageLbl\t\t: "Зураг",\r\n
InsertImage\t\t\t: "Зураг Оруулах/Засварлах",\r\n
InsertFlashLbl\t\t: "Флаш",\r\n
InsertFlash\t\t\t: "Флаш Оруулах/Засварлах",\r\n
InsertTableLbl\t\t: "Хүснэгт",\r\n
InsertTable\t\t\t: "Хүснэгт Оруулах/Засварлах",\r\n
InsertLineLbl\t\t: "Зураас",\r\n
InsertLine\t\t\t: "Хөндлөн зураас оруулах",\r\n
InsertSpecialCharLbl: "Онцгой тэмдэгт",\r\n
InsertSpecialChar\t: "Онцгой тэмдэгт оруулах",\r\n
InsertSmileyLbl\t\t: "Тодорхойлолт",\r\n
InsertSmiley\t\t: "Тодорхойлолт оруулах",\r\n
About\t\t\t\t: "FCKeditor-н тухай",\r\n
Bold\t\t\t\t: "Тод бүдүүн",\r\n
Italic\t\t\t\t: "Налуу",\r\n
Underline\t\t\t: "Доогуур нь зураастай болгох",\r\n
StrikeThrough\t\t: "Дундуур нь зураастай болгох",\r\n
Subscript\t\t\t: "Суурь болгох",\r\n
Superscript\t\t\t: "Зэрэг болгох",\r\n
LeftJustify\t\t\t: "Зүүн талд байрлуулах",\r\n
CenterJustify\t\t: "Төвд байрлуулах",\r\n
RightJustify\t\t: "Баруун талд байрлуулах",\r\n
BlockJustify\t\t: "Блок хэлбэрээр байрлуулах",\r\n
DecreaseIndent\t\t: "Догол мөр нэмэх",\r\n
IncreaseIndent\t\t: "Догол мөр хасах",\r\n
Blockquote\t\t\t: "Хайрцаглах",\r\n
CreateDiv\t\t\t: "Create Div Container",\t//MISSING\r\n
EditDiv\t\t\t\t: "Edit Div Container",\t//MISSING\r\n
DeleteDiv\t\t\t: "Remove Div Container",\t//MISSING\r\n
Undo\t\t\t\t: "Хүчингүй болгох",\r\n
Redo\t\t\t\t: "Өмнөх үйлдлээ сэргээх",\r\n
NumberedListLbl\t\t: "Дугаарлагдсан жагсаалт",\r\n
NumberedList\t\t: "Дугаарлагдсан жагсаалт Оруулах/Авах",\r\n
BulletedListLbl\t\t: "Цэгтэй жагсаалт",\r\n
BulletedList\t\t: "Цэгтэй жагсаалт Оруулах/Авах",\r\n
ShowTableBorders\t: "Хүснэгтийн хүрээг үзүүлэх",\r\n
ShowDetails\t\t\t: "Деталчлан үзүүлэх",\r\n
Style\t\t\t\t: "Загвар",\r\n
FontFormat\t\t\t: "Формат",\r\n
Font\t\t\t\t: "Фонт",\r\n
FontSize\t\t\t: "Хэмжээ",\r\n
TextColor\t\t\t: "Фонтны өнгө",\r\n
BGColor\t\t\t\t: "Фонны өнгө",\r\n
Source\t\t\t\t: "Код",\r\n
Find\t\t\t\t: "Хайх",\r\n
Replace\t\t\t\t: "Солих",\r\n
SpellCheck\t\t\t: "Үгийн дүрэх шалгах",\r\n
UniversalKeyboard\t: "Униварсал гар",\r\n
PageBreakLbl\t\t: "Хуудас тусгаарлах",\r\n
PageBreak\t\t\t: "Хуудас тусгаарлагч оруулах",\r\n
\r\n
Form\t\t\t: "Форм",\r\n
Checkbox\t\t: "Чекбокс",\r\n
RadioButton\t\t: "Радио товч",\r\n
TextField\t\t: "Техт талбар",\r\n
Textarea\t\t: "Техт орчин",\r\n
HiddenField\t\t: "Нууц талбар",\r\n
Button\t\t\t: "Товч",\r\n
SelectionField\t: "Сонгогч талбар",\r\n
ImageButton\t\t: "Зурагтай товч",\r\n
\r\n
FitWindow\t\t: "editor-н хэмжээг томруулах",\r\n
ShowBlocks\t\t: "Block-уудыг үзүүлэх",\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Холбоос засварлах",\r\n
CellCM\t\t\t\t: "Нүх/зай",\r\n
RowCM\t\t\t\t: "Мөр",\r\n
ColumnCM\t\t\t: "Багана",\r\n
InsertRowAfter\t\t: "Мөр дараа нь оруулах",\r\n
InsertRowBefore\t\t: "Мөр өмнө нь оруулах",\r\n
DeleteRows\t\t\t: "Мөр устгах",\r\n
InsertColumnAfter\t: "Багана дараа нь оруулах",\r\n
InsertColumnBefore\t: "Багана өмнө нь оруулах",\r\n
DeleteColumns\t\t: "Багана устгах",\r\n
InsertCellAfter\t\t: "Нүх/зай дараа нь оруулах",\r\n
InsertCellBefore\t: "Нүх/зай өмнө нь оруулах",\r\n
DeleteCells\t\t\t: "Нүх устгах",\r\n
MergeCells\t\t\t: "Нүх нэгтэх",\r\n
MergeRight\t\t\t: "Баруун тийш нэгтгэх",\r\n
MergeDown\t\t\t: "Доош нэгтгэх",\r\n
HorizontalSplitCell\t: "Нүх/зайг босоогоор нь тусгаарлах",\r\n
VerticalSplitCell\t: "Нүх/зайг хөндлөнгөөр нь тусгаарлах",\r\n
TableDelete\t\t\t: "Хүснэгт устгах",\r\n
CellProperties\t\t: "Нүх/зай зайн шинж чанар",\r\n
TableProperties\t\t: "Хүснэгт",\r\n
ImageProperties\t\t: "Зураг",\r\n
FlashProperties\t\t: "Флаш шинж чанар",\r\n
\r\n
AnchorProp\t\t\t: "Холбоос шинж чанар",\r\n
ButtonProp\t\t\t: "Товчны шинж чанар",\r\n
CheckboxProp\t\t: "Чекбоксны шинж чанар",\r\n
HiddenFieldProp\t\t: "Нууц талбарын шинж чанар",\r\n
RadioButtonProp\t\t: "Радио товчны шинж чанар",\r\n
ImageButtonProp\t\t: "Зурган товчны шинж чанар",\r\n
TextFieldProp\t\t: "Текст талбарын шинж чанар",\r\n
SelectionFieldProp\t: "Согогч талбарын шинж чанар",\r\n
TextareaProp\t\t: "Текст орчны шинж чанар",\r\n
FormProp\t\t\t: "Форм шинж чанар",\r\n
\r\n
FontFormats\t\t\t: "Хэвийн;Formatted;Хаяг;Heading 1;Heading 2;Heading 3;Heading 4;Heading 5;Heading 6;Paragraph (DIV)",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "XHTML үйл явц явагдаж байна. Хүлээнэ үү...",\r\n
Done\t\t\t\t: "Хийх",\r\n
PasteWordConfirm\t: "Word-оос хуулсан текстээ санаж байгааг нь буулгахыг та хүсч байна уу. Та текст-ээ буулгахын өмнө цэвэрлэх үү?",\r\n
NotCompatiblePaste\t: "Энэ комманд Internet Explorer-ын 5.5 буюу түүнээс дээш хувилбарт идвэхшинэ. Та цэвэрлэхгүйгээр буулгахыг хүсч байна?",\r\n
UnknownToolbarItem\t: "Багажны хэсгийн \\"%1\\" item мэдэгдэхгүй байна",\r\n
UnknownCommand\t\t: "\\"%1\\" комманд нэр мэдагдэхгүй байна",\r\n
NotImplemented\t\t: "Зөвшөөрөгдөхгүй комманд",\r\n
UnknownToolbarSet\t: "Багажны хэсэгт \\"%1\\" оноох, үүсээгүй байна",\r\n
NoActiveX\t\t\t: "Таны үзүүлэгч/browser-н хамгаалалтын тохиргоо editor-н зарим боломжийг хязгаарлаж байна. Та \\"Run ActiveX controls ба plug-ins\\" сонголыг идвэхитэй болго.",\r\n
BrowseServerBlocked : "Нөөц үзүүгч нээж чадсангүй. Бүх popup blocker-г disabled болгоно уу.",\r\n
DialogBlocked\t\t: "Харилцах цонхонд энийг нээхэд боломжгүй ээ. Бүх popup blocker-г disabled болгоно уу.",\r\n
VisitLinkBlocked\t: "It was not possible to open a new window. Make sure all popup blockers are disabled.",\t//MISSING\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "OK",\r\n
DlgBtnCancel\t\t: "Болих",\r\n
DlgBtnClose\t\t\t: "Хаах",\r\n
DlgBtnBrowseServer\t: "Сервер харуулах",\r\n
DlgAdvancedTag\t\t: "Нэмэлт",\r\n
DlgOpOther\t\t\t: "<Бусад>",\r\n
DlgInfoTab\t\t\t: "Мэдээлэл",\r\n
DlgAlertUrl\t\t\t: "URL оруулна уу",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<Оноохгүй>",\r\n
DlgGenId\t\t\t: "Id",\r\n
DlgGenLangDir\t\t: "Хэлний чиглэл",\r\n
DlgGenLangDirLtr\t: "Зүүнээс баруун (LTR)",\r\n
DlgGenLangDirRtl\t: "Баруунаас зүүн (RTL)",\r\n
DlgGenLangCode\t\t: "Хэлний код",\r\n
DlgGenAccessKey\t\t: "Холбох түлхүүр",\r\n
DlgGenName\t\t\t: "Нэр",\r\n
DlgGenTabIndex\t\t: "Tab индекс",\r\n
DlgGenLongDescr\t\t: "URL-ын тайлбар",\r\n
DlgGenClass\t\t\t: "Stylesheet классууд",\r\n
DlgGenTitle\t\t\t: "Зөвлөлдөх гарчиг",\r\n
DlgGenContType\t\t: "Зөвлөлдөх төрлийн агуулга",\r\n
DlgGenLinkCharset\t: "Тэмдэгт оноох нөөцөд холбогдсон",\r\n
DlgGenStyle\t\t\t: "Загвар",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Зураг",\r\n
DlgImgInfoTab\t\t: "Зурагны мэдээлэл",\r\n
DlgImgBtnUpload\t\t: "Үүнийг сервэррүү илгээ",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "Хуулах",\r\n
DlgImgAlt\t\t\t: "Тайлбар текст",\r\n
DlgImgWidth\t\t\t: "Өргөн",\r\n
DlgImgHeight\t\t: "Өндөр",\r\n
DlgImgLockRatio\t\t: "Радио түгжих",\r\n
DlgBtnResetSize\t\t: "хэмжээ дахин оноох",\r\n
DlgImgBorder\t\t: "Хүрээ",\r\n
DlgImgHSpace\t\t: "Хөндлөн зай",\r\n
DlgImgVSpace\t\t: "Босоо зай",\r\n
DlgImgAlign\t\t\t: "Эгнээ",\r\n
DlgImgAlignLeft\t\t: "Зүүн",\r\n
DlgImgAlignAbsBottom: "Abs доод талд",\r\n
DlgImgAlignAbsMiddle: "Abs Дунд талд",\r\n
DlgImgAlignBaseline\t: "Baseline",\r\n
DlgImgAlignBottom\t: "Доод талд",\r\n
DlgImgAlignMiddle\t: "Дунд талд",\r\n
DlgImgAlignRight\t: "Баруун",\r\n
DlgImgAlignTextTop\t: "Текст дээр",\r\n
DlgImgAlignTop\t\t: "Дээд талд",\r\n
DlgImgPreview\t\t: "Уридчлан харах",\r\n
DlgImgAlertUrl\t\t: "Зурагны URL-ын төрлийн сонгоно уу",\r\n
DlgImgLinkTab\t\t: "Линк",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Флаш  шинж чанар",\r\n
DlgFlashChkPlay\t\t: "Автоматаар тоглох",\r\n
DlgFlashChkLoop\t\t: "Давтах",\r\n
DlgFlashChkMenu\t\t: "Флаш цэс идвэхжүүлэх",\r\n
DlgFlashScale\t\t: "Өргөгтгөх",\r\n
DlgFlashScaleAll\t: "Бүгдийг харуулах",\r\n
DlgFlashScaleNoBorder\t: "Хүрээгүй",\r\n
DlgFlashScaleFit\t: "Яг тааруулах",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Линк",\r\n
DlgLnkInfoTab\t\t: "Линкийн мэдээлэл",\r\n
DlgLnkTargetTab\t\t: "Байрлал",\r\n
\r\n
DlgLnkType\t\t\t: "Линкийн төрөл",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Энэ хуудасандах холбоос",\r\n
DlgLnkTypeEMail\t\t: "E-Mail",\r\n
DlgLnkProto\t\t\t: "Протокол",\r\n
DlgLnkProtoOther\t: "<бусад>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Холбоос сонгох",\r\n
DlgLnkAnchorByName\t: "Холбоосын нэрээр",\r\n
DlgLnkAnchorById\t: "Элемэнт Id-гаар",\r\n
DlgLnkNoAnchors\t\t: "(Баримт бичиг холбоосгүй байна)",\r\n
DlgLnkEMail\t\t\t: "E-Mail Хаяг",\r\n
DlgLnkEMailSubject\t: "Message гарчиг",\r\n
DlgLnkEMailBody\t\t: "Message-ийн агуулга",\r\n
DlgLnkUpload\t\t: "Хуулах",\r\n
DlgLnkBtnUpload\t\t: "Үүнийг серверрүү илгээ",\r\n
\r\n
DlgLnkTarget\t\t: "Байрлал",\r\n
DlgLnkTargetFrame\t: "<Агуулах хүрээ>",\r\n
DlgLnkTargetPopup\t: "<popup цонх>",\r\n
DlgLnkTargetBlank\t: "Шинэ цонх (_blank)",\r\n
DlgLnkTargetParent\t: "Эцэг цонх (_parent)",\r\n
DlgLnkTargetSelf\t: "Төстэй цонх (_self)",\r\n
DlgLnkTargetTop\t\t: "Хамгийн түрүүн байх цонх (_top)",\r\n
DlgLnkTargetFrameName\t: "Очих фремын нэр",\r\n
DlgLnkPopWinName\t: "Popup цонхны нэр",\r\n
DlgLnkPopWinFeat\t: "Popup цонхны онцлог",\r\n
DlgLnkPopResize\t\t: "Хэмжээ өөрчлөх",\r\n
DlgLnkPopLocation\t: "Location хэсэг",\r\n
DlgLnkPopMenu\t\t: "Meню хэсэг",\r\n
DlgLnkPopScroll\t\t: "Скрол хэсэгүүд",\r\n
DlgLnkPopStatus\t\t: "Статус хэсэг",\r\n
DlgLnkPopToolbar\t: "Багажны хэсэг",\r\n
DlgLnkPopFullScrn\t: "Цонх дүүргэх (IE)",\r\n
DlgLnkPopDependent\t: "Хамаатай (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Өргөн",\r\n
DlgLnkPopHeight\t\t: "Өндөр",\r\n
DlgLnkPopLeft\t\t: "Зүүн байрлал",\r\n
DlgLnkPopTop\t\t: "Дээд байрлал",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Линк URL-ээ төрөлжүүлнэ үү",\r\n
DlnLnkMsgNoEMail\t: "Е-mail хаягаа төрөлжүүлнэ үү",\r\n
DlnLnkMsgNoAnchor\t: "Холбоосоо сонгоно уу",\r\n
DlnLnkMsgInvPopName\t: "popup нэр нь үсгэн тэмдэгтээр эхэлсэн байх ба хоосон зай агуулаагүй байх ёстой.",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Өнгө сонгох",\r\n
DlgColorBtnClear\t: "Цэвэрлэх",\r\n
DlgColorHighlight\t: "Өнгө",\r\n
DlgColorSelected\t: "Сонгогдсон",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Тодорхойлолт оруулах",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Онцгой тэмдэгт сонгох",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Хүснэгт",\r\n
DlgTableRows\t\t: "Мөр",\r\n
DlgTableColumns\t\t: "Багана",\r\n
DlgTableBorder\t\t: "Хүрээний хэмжээ",\r\n
DlgTableAlign\t\t: "Эгнээ",\r\n
DlgTableAlignNotSet\t: "<Оноохгүй>",\r\n
DlgTableAlignLeft\t: "Зүүн талд",\r\n
DlgTableAlignCenter\t: "Төвд",\r\n
DlgTableAlignRight\t: "Баруун талд",\r\n
DlgTableWidth\t\t: "Өргөн",\r\n
DlgTableWidthPx\t\t: "цэг",\r\n
DlgTableWidthPc\t\t: "хувь",\r\n
DlgTableHeight\t\t: "Өндөр",\r\n
DlgTableCellSpace\t: "Нүх хоорондын зай (spacing)",\r\n
DlgTableCellPad\t\t: "Нүх доторлох(padding)",\r\n
DlgTableCaption\t\t: "Тайлбар",\r\n
DlgTableSummary\t\t: "Тайлбар",\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Хоосон зайн шинж чанар",\r\n
DlgCellWidth\t\t: "Өргөн",\r\n
DlgCellWidthPx\t\t: "цэг",\r\n
DlgCellWidthPc\t\t: "хувь",\r\n
DlgCellHeight\t\t: "Өндөр",\r\n
DlgCellWordWrap\t\t: "Үг таслах",\r\n
DlgCellWordWrapNotSet\t: "<Оноохгүй>",\r\n
DlgCellWordWrapYes\t: "Тийм",\r\n
DlgCellWordWrapNo\t: "Үгүй",\r\n
DlgCellHorAlign\t\t: "Босоо эгнээ",\r\n
DlgCellHorAlignNotSet\t: "<Оноохгүй>",\r\n
DlgCellHorAlignLeft\t: "Зүүн",\r\n
DlgCellHorAlignCenter\t: "Төв",\r\n
DlgCellHorAlignRight: "Баруун",\r\n
DlgCellVerAlign\t\t: "Хөндлөн эгнээ",\r\n
DlgCellVerAlignNotSet\t: "<Оноохгүй>",\r\n
DlgCellVerAlignTop\t: "Дээд тал",\r\n
DlgCellVerAlignMiddle\t: "Дунд",\r\n
DlgCellVerAlignBottom\t: "Доод тал",\r\n
DlgCellVerAlignBaseline\t: "Baseline",\r\n
DlgCellType\t\t: "Cell Type",\t//MISSING\r\n
DlgCellTypeData\t\t: "Data",\t//MISSING\r\n
DlgCellTypeHeader\t: "Header",\t//MISSING\r\n
DlgCellRowSpan\t\t: "Нийт мөр (span)",\r\n
DlgCellCollSpan\t\t: "Нийт багана (span)",\r\n
DlgCellBackColor\t: "Фонны өнгө",\r\n
DlgCellBorderColor\t: "Хүрээний өнгө",\r\n
DlgCellBtnSelect\t: "Сонго...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Хай мөн Дарж бич",\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Хайх",\r\n
DlgFindFindBtn\t\t: "Хайх",\r\n
DlgFindNotFoundMsg\t: "Хайсан текст олсонгүй.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Солих",\r\n
DlgReplaceFindLbl\t\t: "Хайх үг/үсэг:",\r\n
DlgReplaceReplaceLbl\t: "Солих үг:",\r\n
DlgReplaceCaseChk\t\t: "Тэнцэх төлөв",\r\n
DlgReplaceReplaceBtn\t: "Солих",\r\n
DlgReplaceReplAllBtn\t: "Бүгдийг нь Солих",\r\n
DlgReplaceWordChk\t\t: "Тэнцэх бүтэн үг",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "Таны browser-ын хамгаалалтын тохиргоо editor-д автоматаар хайчлах үйлдэлийг зөвшөөрөхгүй байна. (Ctrl+X) товчны хослолыг ашиглана уу.",\r\n
PasteErrorCopy\t: "Таны browser-ын хамгаалалтын тохиргоо editor-д автоматаар хуулах үйлдэлийг зөвшөөрөхгүй байна. (Ctrl+C) товчны хослолыг ашиглана уу.",\r\n
\r\n
PasteAsText\t\t: "Plain Text-ээс буулгах",\r\n
PasteFromWord\t: "Word-оос буулгах",\r\n
\r\n
DlgPasteMsg2\t: "(<strong>Ctrl+V</strong>) товчийг ашиглан paste хийнэ үү. Мөн <strong>OK</strong> дар.",\r\n
DlgPasteSec\t\t: "Таны үзүүлэгч/browser/-н хамгаалалтын тохиргооноос болоод editor clipboard өгөгдөлрүү шууд хандах боломжгүй. Энэ цонход дахин paste хийхийг оролд.",\r\n
DlgPasteIgnoreFont\t\t: "Тодорхойлогдсон Font Face зөвшөөрнө",\r\n
DlgPasteRemoveStyles\t: "Тодорхойлогдсон загварыг авах",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Автоматаар",\r\n
ColorMoreColors\t: "Нэмэлт өнгөнүүд...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Баримт бичиг шинж чанар",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Холбоос шинж чанар",\r\n
DlgAnchorName\t\t: "Холбоос нэр",\r\n
DlgAnchorErrorName\t: "Холбоос төрөл оруулна уу",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Толь бичиггүй",\r\n
DlgSpellChangeTo\t\t: "Өөрчлөх",\r\n
DlgSpellBtnIgnore\t\t: "Зөвшөөрөх",\r\n
DlgSpellBtnIgnoreAll\t: "Бүгдийг зөвшөөрөх",\r\n
DlgSpellBtnReplace\t\t: "Дарж бичих",\r\n
DlgSpellBtnReplaceAll\t: "Бүгдийг Дарж бичих",\r\n
DlgSpellBtnUndo\t\t\t: "Буцаах",\r\n
DlgSpellNoSuggestions\t: "- Тайлбаргүй -",\r\n
DlgSpellProgress\t\t: "Дүрэм шалгаж байгаа үйл явц...",\r\n
DlgSpellNoMispell\t\t: "Дүрэм шалгаад дууссан: Алдаа олдсонгүй",\r\n
DlgSpellNoChanges\t\t: "Дүрэм шалгаад дууссан: үг өөрчлөгдөөгүй",\r\n
DlgSpellOneChange\t\t: "Дүрэм шалгаад дууссан: 1 үг өөрчлөгдсөн",\r\n
DlgSpellManyChanges\t\t: "Дүрэм шалгаад дууссан: %1 үг өөрчлөгдсөн",\r\n
\r\n
IeSpellDownload\t\t\t: "Дүрэм шалгагч суугаагүй байна. Татаж авахыг хүсч байна уу?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Тэкст (Утга)",\r\n
DlgButtonType\t\t: "Төрөл",\r\n
DlgButtonTypeBtn\t: "Товч",\r\n
DlgButtonTypeSbm\t: "Submit",\r\n
DlgButtonTypeRst\t: "Болих",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Нэр",\r\n
DlgCheckboxValue\t: "Утга",\r\n
DlgCheckboxSelected\t: "Сонгогдсон",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Нэр",\r\n
DlgFormAction\t: "Үйлдэл",\r\n
DlgFormMethod\t: "Арга",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Нэр",\r\n
DlgSelectValue\t\t: "Утга",\r\n
DlgSelectSize\t\t: "Хэмжээ",\r\n
DlgSelectLines\t\t: "Мөр",\r\n
DlgSelectChkMulti\t: "Олон сонголт зөвшөөрөх",\r\n
DlgSelectOpAvail\t: "Идвэхтэй сонголт",\r\n
DlgSelectOpText\t\t: "Тэкст",\r\n
DlgSelectOpValue\t: "Утга",\r\n
DlgSelectBtnAdd\t\t: "Нэмэх",\r\n
DlgSelectBtnModify\t: "Өөрчлөх",\r\n
DlgSelectBtnUp\t\t: "Дээш",\r\n
DlgSelectBtnDown\t: "Доош",\r\n
DlgSelectBtnSetValue : "Сонгогдсан утга оноох",\r\n
DlgSelectBtnDelete\t: "Устгах",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Нэр",\r\n
DlgTextareaCols\t: "Багана",\r\n
DlgTextareaRows\t: "Мөр",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Нэр",\r\n
DlgTextValue\t\t: "Утга",\r\n
DlgTextCharWidth\t: "Тэмдэгтын өргөн",\r\n
DlgTextMaxChars\t\t: "Хамгийн их тэмдэгт",\r\n
DlgTextType\t\t\t: "Төрөл",\r\n
DlgTextTypeText\t\t: "Текст",\r\n
DlgTextTypePass\t\t: "Нууц үг",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Нэр",\r\n
DlgHiddenValue\t: "Утга",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Bulleted жагсаалын шинж чанар",\r\n
NumberedListProp\t: "Дугаарласан жагсаалын шинж чанар",\r\n
DlgLstStart\t\t\t: "Эхлэх",\r\n
DlgLstType\t\t\t: "Төрөл",\r\n
DlgLstTypeCircle\t: "Тойрог",\r\n
DlgLstTypeDisc\t\t: "Тайлбар",\r\n
DlgLstTypeSquare\t: "Square",\r\n
DlgLstTypeNumbers\t: "Тоо (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Жижиг үсэг (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Том үсэг (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Жижиг Ром тоо (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Том Ром тоо (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Ерөнхий",\r\n
DlgDocBackTab\t\t: "Фоно",\r\n
DlgDocColorsTab\t\t: "Захын зай ба Өнгө",\r\n
DlgDocMetaTab\t\t: "Meta өгөгдөл",\r\n
\r\n
DlgDocPageTitle\t\t: "Хуудасны гарчиг",\r\n
DlgDocLangDir\t\t: "Хэлний чиглэл",\r\n
DlgDocLangDirLTR\t: "Зүүнээс баруунруу (LTR)",\r\n
DlgDocLangDirRTL\t: "Баруунаас зүүнрүү (RTL)",\r\n
DlgDocLangCode\t\t: "Хэлний код",\r\n
DlgDocCharSet\t\t: "Encoding тэмдэгт",\r\n
DlgDocCharSetCE\t\t: "Төв европ",\r\n
DlgDocCharSetCT\t\t: "Хятадын уламжлалт (Big5)",\r\n
DlgDocCharSetCR\t\t: "Крил",\r\n
DlgDocCharSetGR\t\t: "Гред",\r\n
DlgDocCharSetJP\t\t: "Япон",\r\n
DlgDocCharSetKR\t\t: "Солонгос",\r\n
DlgDocCharSetTR\t\t: "Tурк",\r\n
DlgDocCharSetUN\t\t: "Юникод (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "Баруун европ",\r\n
DlgDocCharSetOther\t: "Encoding-д өөр тэмдэгт оноох",\r\n
\r\n
DlgDocDocType\t\t: "Баримт бичгийн төрөл Heading",\r\n
DlgDocDocTypeOther\t: "Бусад баримт бичгийн төрөл Heading",\r\n
DlgDocIncXHTML\t\t: "XHTML агуулж зарлах",\r\n
DlgDocBgColor\t\t: "Фоно өнгө",\r\n
DlgDocBgImage\t\t: "Фоно зурагны URL",\r\n
DlgDocBgNoScroll\t: "Гүйдэггүй фоно",\r\n
DlgDocCText\t\t\t: "Текст",\r\n
DlgDocCLink\t\t\t: "Линк",\r\n
DlgDocCVisited\t\t: "Зочилсон линк",\r\n
DlgDocCActive\t\t: "Идвэхитэй линк",\r\n
DlgDocMargins\t\t: "Хуудасны захын зай",\r\n
DlgDocMaTop\t\t\t: "Дээд тал",\r\n
DlgDocMaLeft\t\t: "Зүүн тал",\r\n
DlgDocMaRight\t\t: "Баруун тал",\r\n
DlgDocMaBottom\t\t: "Доод тал",\r\n
DlgDocMeIndex\t\t: "Баримт бичгийн индекс түлхүүр үг (таслалаар тусгаарлагдана)",\r\n
DlgDocMeDescr\t\t: "Баримт бичгийн тайлбар",\r\n
DlgDocMeAuthor\t\t: "Зохиогч",\r\n
DlgDocMeCopy\t\t: "Зохиогчийн эрх",\r\n
DlgDocPreview\t\t: "Харах",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Загварууд",\r\n
DlgTemplatesTitle\t: "Загварын агуулга",\r\n
DlgTemplatesSelMsg\t: "Загварыг нээж editor-рүү сонгож оруулна уу<br />(Одоогийн агууллагыг устаж магадгүй):",\r\n
DlgTemplatesLoading\t: "Загваруудыг ачааллаж байна. Түр хүлээнэ үү...",\r\n
DlgTemplatesNoTpl\t: "(Загвар тодорхойлогдоогүй байна)",\r\n
DlgTemplatesReplace\t: "Одоогийн агууллагыг дарж бичих",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Тухай",\r\n
DlgAboutBrowserInfoTab\t: "Мэдээлэл үзүүлэгч",\r\n
DlgAboutLicenseTab\t: "Лиценз",\r\n
DlgAboutVersion\t\t: "Хувилбар",\r\n
DlgAboutInfo\t\t: "Мэдээллээр туслах",\r\n
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
            <value> <int>23904</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
