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
            <value> <string>ts83858910.16</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>uk.js</string> </value>
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
 * Ukrainian language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Згорнути панель інструментів",\r\n
ToolbarExpand\t\t: "Розгорнути панель інструментів",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Зберегти",\r\n
NewPage\t\t\t\t: "Нова сторінка",\r\n
Preview\t\t\t\t: "Попередній перегляд",\r\n
Cut\t\t\t\t\t: "Вирізати",\r\n
Copy\t\t\t\t: "Копіювати",\r\n
Paste\t\t\t\t: "Вставити",\r\n
PasteText\t\t\t: "Вставити тільки текст",\r\n
PasteWord\t\t\t: "Вставити з Word",\r\n
Print\t\t\t\t: "Друк",\r\n
SelectAll\t\t\t: "Виділити все",\r\n
RemoveFormat\t\t: "Прибрати форматування",\r\n
InsertLinkLbl\t\t: "Посилання",\r\n
InsertLink\t\t\t: "Вставити/Редагувати посилання",\r\n
RemoveLink\t\t\t: "Знищити посилання",\r\n
VisitLink\t\t\t: "Відкрити посилання",\r\n
Anchor\t\t\t\t: "Вставити/Редагувати якір",\r\n
AnchorDelete\t\t: "Видалити якір",\r\n
InsertImageLbl\t\t: "Зображення",\r\n
InsertImage\t\t\t: "Вставити/Редагувати зображення",\r\n
InsertFlashLbl\t\t: "Flash",\r\n
InsertFlash\t\t\t: "Вставити/Редагувати Flash",\r\n
InsertTableLbl\t\t: "Таблиця",\r\n
InsertTable\t\t\t: "Вставити/Редагувати таблицю",\r\n
InsertLineLbl\t\t: "Лінія",\r\n
InsertLine\t\t\t: "Вставити горизонтальну лінію",\r\n
InsertSpecialCharLbl: "Спеціальний символ",\r\n
InsertSpecialChar\t: "Вставити спеціальний символ",\r\n
InsertSmileyLbl\t\t: "Смайлик",\r\n
InsertSmiley\t\t: "Вставити смайлик",\r\n
About\t\t\t\t: "Про FCKeditor",\r\n
Bold\t\t\t\t: "Жирний",\r\n
Italic\t\t\t\t: "Курсив",\r\n
Underline\t\t\t: "Підкреслений",\r\n
StrikeThrough\t\t: "Закреслений",\r\n
Subscript\t\t\t: "Підрядковий індекс",\r\n
Superscript\t\t\t: "Надрядковий индекс",\r\n
LeftJustify\t\t\t: "По лівому краю",\r\n
CenterJustify\t\t: "По центру",\r\n
RightJustify\t\t: "По правому краю",\r\n
BlockJustify\t\t: "По ширині",\r\n
DecreaseIndent\t\t: "Зменшити відступ",\r\n
IncreaseIndent\t\t: "Збільшити відступ",\r\n
Blockquote\t\t\t: "Цитата",\r\n
CreateDiv\t\t\t: "Створити Div контейнер",\r\n
EditDiv\t\t\t\t: "Редагувати Div контейнер",\r\n
DeleteDiv\t\t\t: "Видалити Div контейнер",\r\n
Undo\t\t\t\t: "Повернути",\r\n
Redo\t\t\t\t: "Повторити",\r\n
NumberedListLbl\t\t: "Нумерований список",\r\n
NumberedList\t\t: "Вставити/Видалити нумерований список",\r\n
BulletedListLbl\t\t: "Маркований список",\r\n
BulletedList\t\t: "Вставити/Видалити маркований список",\r\n
ShowTableBorders\t: "Показати бордюри таблиці",\r\n
ShowDetails\t\t\t: "Показати деталі",\r\n
Style\t\t\t\t: "Стиль",\r\n
FontFormat\t\t\t: "Форматування",\r\n
Font\t\t\t\t: "Шрифт",\r\n
FontSize\t\t\t: "Розмір",\r\n
TextColor\t\t\t: "Колір тексту",\r\n
BGColor\t\t\t\t: "Колір фону",\r\n
Source\t\t\t\t: "Джерело",\r\n
Find\t\t\t\t: "Пошук",\r\n
Replace\t\t\t\t: "Заміна",\r\n
SpellCheck\t\t\t: "Перевірити орфографію",\r\n
UniversalKeyboard\t: "Універсальна клавіатура",\r\n
PageBreakLbl\t\t: "Розривши сторінки",\r\n
PageBreak\t\t\t: "Вставити розривши сторінки",\r\n
\r\n
Form\t\t\t: "Форма",\r\n
Checkbox\t\t: "Флагова кнопка",\r\n
RadioButton\t\t: "Кнопка вибору",\r\n
TextField\t\t: "Текстове поле",\r\n
Textarea\t\t: "Текстова область",\r\n
HiddenField\t\t: "Приховане поле",\r\n
Button\t\t\t: "Кнопка",\r\n
SelectionField\t: "Список",\r\n
ImageButton\t\t: "Кнопка із зображенням",\r\n
\r\n
FitWindow\t\t: "Розвернути вікно редактора",\r\n
ShowBlocks\t\t: "Показувати блоки",\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Вставити посилання",\r\n
CellCM\t\t\t\t: "Осередок",\r\n
RowCM\t\t\t\t: "Рядок",\r\n
ColumnCM\t\t\t: "Колонка",\r\n
InsertRowAfter\t\t: "Вставити рядок після",\r\n
InsertRowBefore\t\t: "Вставити рядок до",\r\n
DeleteRows\t\t\t: "Видалити строки",\r\n
InsertColumnAfter\t: "Вставити колонку після",\r\n
InsertColumnBefore\t: "Вставити колонку до",\r\n
DeleteColumns\t\t: "Видалити колонки",\r\n
InsertCellAfter\t\t: "Вставити комірку після",\r\n
InsertCellBefore\t: "Вставити комірку до",\r\n
DeleteCells\t\t\t: "Видалити комірки",\r\n
MergeCells\t\t\t: "Об\'єднати комірки",\r\n
MergeRight\t\t\t: "Об\'єднати зправа",\r\n
MergeDown\t\t\t: "Об\'єднати до низу",\r\n
HorizontalSplitCell\t: "Розділити комірку по горизонталі",\r\n
VerticalSplitCell\t: "Розділити комірку по вертикалі",\r\n
TableDelete\t\t\t: "Видалити таблицю",\r\n
CellProperties\t\t: "Властивості комірки",\r\n
TableProperties\t\t: "Властивості таблиці",\r\n
ImageProperties\t\t: "Властивості зображення",\r\n
FlashProperties\t\t: "Властивості Flash",\r\n
\r\n
AnchorProp\t\t\t: "Властивості якоря",\r\n
ButtonProp\t\t\t: "Властивості кнопки",\r\n
CheckboxProp\t\t: "Властивості флагової кнопки",\r\n
HiddenFieldProp\t\t: "Властивості прихованого поля",\r\n
RadioButtonProp\t\t: "Властивості кнопки вибору",\r\n
ImageButtonProp\t\t: "Властивості кнопки із зображенням",\r\n
TextFieldProp\t\t: "Властивості текстового поля",\r\n
SelectionFieldProp\t: "Властивості списку",\r\n
TextareaProp\t\t: "Властивості текстової області",\r\n
FormProp\t\t\t: "Властивості форми",\r\n
\r\n
FontFormats\t\t\t: "Нормальний;Форматований;Адреса;Заголовок 1;Заголовок 2;Заголовок 3;Заголовок 4;Заголовок 5;Заголовок 6;Нормальний (DIV)",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "Обробка XHTML. Зачекайте, будь ласка...",\r\n
Done\t\t\t\t: "Зроблено",\r\n
PasteWordConfirm\t: "Текст, що ви хочете вставити, схожий на копійований з Word. Ви хочете очистити його перед вставкою?",\r\n
NotCompatiblePaste\t: "Ця команда доступна для Internet Explorer версії 5.5 або вище. Ви хочете вставити без очищення?",\r\n
UnknownToolbarItem\t: "Невідомий елемент панелі інструментів \\"%1\\"",\r\n
UnknownCommand\t\t: "Невідоме ім\'я команди \\"%1\\"",\r\n
NotImplemented\t\t: "Команда не реалізована",\r\n
UnknownToolbarSet\t: "Панель інструментів \\"%1\\" не існує",\r\n
NoActiveX\t\t\t: "Настройки безпеки вашого браузера можуть обмежувати деякі властивості редактора. Ви повинні включити опцію \\"Запускати елементи управління ACTIVEX і плугіни\\". Ви можете бачити помилки і помічати відсутність можливостей.",\r\n
BrowseServerBlocked : "Ресурси браузера не можуть бути відкриті. Перевірте що блокування спливаючих вікон вимкнені.",\r\n
DialogBlocked\t\t: "Не можливо відкрити вікно діалогу. Перевірте що блокування спливаючих вікон вимкнені.",\r\n
VisitLinkBlocked\t: "It was not possible to open a new window. Make sure all popup blockers are disabled.",\t//MISSING\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "ОК",\r\n
DlgBtnCancel\t\t: "Скасувати",\r\n
DlgBtnClose\t\t\t: "Зачинити",\r\n
DlgBtnBrowseServer\t: "Передивитися на сервері",\r\n
DlgAdvancedTag\t\t: "Розширений",\r\n
DlgOpOther\t\t\t: "<Інше>",\r\n
DlgInfoTab\t\t\t: "Інфо",\r\n
DlgAlertUrl\t\t\t: "Вставте, будь-ласка, URL",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<не визначено>",\r\n
DlgGenId\t\t\t: "Ідентифікатор",\r\n
DlgGenLangDir\t\t: "Напрямок мови",\r\n
DlgGenLangDirLtr\t: "Зліва на право (LTR)",\r\n
DlgGenLangDirRtl\t: "Зправа на ліво (RTL)",\r\n
DlgGenLangCode\t\t: "Мова",\r\n
DlgGenAccessKey\t\t: "Гаряча клавіша",\r\n
DlgGenName\t\t\t: "Им\'я",\r\n
DlgGenTabIndex\t\t: "Послідовність переходу",\r\n
DlgGenLongDescr\t\t: "Довгий опис URL",\r\n
DlgGenClass\t\t\t: "Клас CSS",\r\n
DlgGenTitle\t\t\t: "Заголовок",\r\n
DlgGenContType\t\t: "Тип вмісту",\r\n
DlgGenLinkCharset\t: "Кодировка",\r\n
DlgGenStyle\t\t\t: "Стиль CSS",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Властивості зображення",\r\n
DlgImgInfoTab\t\t: "Інформація про изображении",\r\n
DlgImgBtnUpload\t\t: "Надіслати на сервер",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "Закачати",\r\n
DlgImgAlt\t\t\t: "Альтернативний текст",\r\n
DlgImgWidth\t\t\t: "Ширина",\r\n
DlgImgHeight\t\t: "Висота",\r\n
DlgImgLockRatio\t\t: "Зберегти пропорції",\r\n
DlgBtnResetSize\t\t: "Скинути розмір",\r\n
DlgImgBorder\t\t: "Бордюр",\r\n
DlgImgHSpace\t\t: "Горизонтальний відступ",\r\n
DlgImgVSpace\t\t: "Вертикальний відступ",\r\n
DlgImgAlign\t\t\t: "Вирівнювання",\r\n
DlgImgAlignLeft\t\t: "По лівому краю",\r\n
DlgImgAlignAbsBottom: "Абс по низу",\r\n
DlgImgAlignAbsMiddle: "Абс по середині",\r\n
DlgImgAlignBaseline\t: "По базовій лінії",\r\n
DlgImgAlignBottom\t: "По низу",\r\n
DlgImgAlignMiddle\t: "По середині",\r\n
DlgImgAlignRight\t: "По правому краю",\r\n
DlgImgAlignTextTop\t: "Текст на верху",\r\n
DlgImgAlignTop\t\t: "По верху",\r\n
DlgImgPreview\t\t: "Попередній перегляд",\r\n
DlgImgAlertUrl\t\t: "Будь ласка, введіть URL зображення",\r\n
DlgImgLinkTab\t\t: "Посилання",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Властивості Flash",\r\n
DlgFlashChkPlay\t\t: "Авто програвання",\r\n
DlgFlashChkLoop\t\t: "Зациклити",\r\n
DlgFlashChkMenu\t\t: "Дозволити меню Flash",\r\n
DlgFlashScale\t\t: "Масштаб",\r\n
DlgFlashScaleAll\t: "Показати всі",\r\n
DlgFlashScaleNoBorder\t: "Без рамки",\r\n
DlgFlashScaleFit\t: "Дійсний розмір",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Посилання",\r\n
DlgLnkInfoTab\t\t: "Інформація посилання",\r\n
DlgLnkTargetTab\t\t: "Ціль",\r\n
\r\n
DlgLnkType\t\t\t: "Тип посилання",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Якір на цю сторінку",\r\n
DlgLnkTypeEMail\t\t: "Эл. пошта",\r\n
DlgLnkProto\t\t\t: "Протокол",\r\n
DlgLnkProtoOther\t: "<інше>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Оберіть якір",\r\n
DlgLnkAnchorByName\t: "За ім\'ям якоря",\r\n
DlgLnkAnchorById\t: "За ідентифікатором елемента",\r\n
DlgLnkNoAnchors\t\t: "(Немає якорів доступних в цьому документі)",\r\n
DlgLnkEMail\t\t\t: "Адреса ел. пошти",\r\n
DlgLnkEMailSubject\t: "Тема листа",\r\n
DlgLnkEMailBody\t\t: "Тіло повідомлення",\r\n
DlgLnkUpload\t\t: "Закачати",\r\n
DlgLnkBtnUpload\t\t: "Переслати на сервер",\r\n
\r\n
DlgLnkTarget\t\t: "Ціль",\r\n
DlgLnkTargetFrame\t: "<фрейм>",\r\n
DlgLnkTargetPopup\t: "<спливаюче вікно>",\r\n
DlgLnkTargetBlank\t: "Нове вікно (_blank)",\r\n
DlgLnkTargetParent\t: "Батьківське вікно (_parent)",\r\n
DlgLnkTargetSelf\t: "Теж вікно (_self)",\r\n
DlgLnkTargetTop\t\t: "Найвище вікно (_top)",\r\n
DlgLnkTargetFrameName\t: "Ім\'я целевого фрейма",\r\n
DlgLnkPopWinName\t: "Ім\'я спливаючого вікна",\r\n
DlgLnkPopWinFeat\t: "Властивості спливаючого вікна",\r\n
DlgLnkPopResize\t\t: "Змінюється в розмірах",\r\n
DlgLnkPopLocation\t: "Панель локації",\r\n
DlgLnkPopMenu\t\t: "Панель меню",\r\n
DlgLnkPopScroll\t\t: "Полоси прокрутки",\r\n
DlgLnkPopStatus\t\t: "Строка статусу",\r\n
DlgLnkPopToolbar\t: "Панель інструментів",\r\n
DlgLnkPopFullScrn\t: "Повний екран (IE)",\r\n
DlgLnkPopDependent\t: "Залежний (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Ширина",\r\n
DlgLnkPopHeight\t\t: "Висота",\r\n
DlgLnkPopLeft\t\t: "Позиція зліва",\r\n
DlgLnkPopTop\t\t: "Позиція зверху",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Будь ласка, занесіть URL посилання",\r\n
DlnLnkMsgNoEMail\t: "Будь ласка, занесіть адрес эл. почты",\r\n
DlnLnkMsgNoAnchor\t: "Будь ласка, оберіть якір",\r\n
DlnLnkMsgInvPopName\t: "Назва спливаючого вікна повинна починатися букви і не може містити пропусків",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Оберіть колір",\r\n
DlgColorBtnClear\t: "Очистити",\r\n
DlgColorHighlight\t: "Підсвічений",\r\n
DlgColorSelected\t: "Обраний",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Вставити смайлик",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Оберіть спеціальний символ",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Властивості таблиці",\r\n
DlgTableRows\t\t: "Строки",\r\n
DlgTableColumns\t\t: "Колонки",\r\n
DlgTableBorder\t\t: "Розмір бордюра",\r\n
DlgTableAlign\t\t: "Вирівнювання",\r\n
DlgTableAlignNotSet\t: "<Не вст.>",\r\n
DlgTableAlignLeft\t: "Зліва",\r\n
DlgTableAlignCenter\t: "По центру",\r\n
DlgTableAlignRight\t: "Зправа",\r\n
DlgTableWidth\t\t: "Ширина",\r\n
DlgTableWidthPx\t\t: "пікселів",\r\n
DlgTableWidthPc\t\t: "відсотків",\r\n
DlgTableHeight\t\t: "Висота",\r\n
DlgTableCellSpace\t: "Проміжок (spacing)",\r\n
DlgTableCellPad\t\t: "Відступ (padding)",\r\n
DlgTableCaption\t\t: "Заголовок",\r\n
DlgTableSummary\t\t: "Резюме",\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Властивості комірки",\r\n
DlgCellWidth\t\t: "Ширина",\r\n
DlgCellWidthPx\t\t: "пікселів",\r\n
DlgCellWidthPc\t\t: "відсотків",\r\n
DlgCellHeight\t\t: "Висота",\r\n
DlgCellWordWrap\t\t: "Згортання текста",\r\n
DlgCellWordWrapNotSet\t: "<Не вст.>",\r\n
DlgCellWordWrapYes\t: "Так",\r\n
DlgCellWordWrapNo\t: "Ні",\r\n
DlgCellHorAlign\t\t: "Горизонтальне вирівнювання",\r\n
DlgCellHorAlignNotSet\t: "<Не вст.>",\r\n
DlgCellHorAlignLeft\t: "Зліва",\r\n
DlgCellHorAlignCenter\t: "По центру",\r\n
DlgCellHorAlignRight: "Зправа",\r\n
DlgCellVerAlign\t\t: "Вертикальное вирівнювання",\r\n
DlgCellVerAlignNotSet\t: "<Не вст.>",\r\n
DlgCellVerAlignTop\t: "Зверху",\r\n
DlgCellVerAlignMiddle\t: "Посередині",\r\n
DlgCellVerAlignBottom\t: "Знизу",\r\n
DlgCellVerAlignBaseline\t: "По базовій лінії",\r\n
DlgCellType\t\t: "Cell Type",\t//MISSING\r\n
DlgCellTypeData\t\t: "Data",\t//MISSING\r\n
DlgCellTypeHeader\t: "Header",\t//MISSING\r\n
DlgCellRowSpan\t\t: "Діапазон строк (span)",\r\n
DlgCellCollSpan\t\t: "Діапазон колонок (span)",\r\n
DlgCellBackColor\t: "Колір фона",\r\n
DlgCellBorderColor\t: "Колір бордюра",\r\n
DlgCellBtnSelect\t: "Оберіть...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Знайти і замінити",\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Пошук",\r\n
DlgFindFindBtn\t\t: "Пошук",\r\n
DlgFindNotFoundMsg\t: "Вказаний текст не знайдений.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Замінити",\r\n
DlgReplaceFindLbl\t\t: "Шукати:",\r\n
DlgReplaceReplaceLbl\t: "Замінити на:",\r\n
DlgReplaceCaseChk\t\t: "Учитывать регистр",\r\n
DlgReplaceReplaceBtn\t: "Замінити",\r\n
DlgReplaceReplAllBtn\t: "Замінити все",\r\n
DlgReplaceWordChk\t\t: "Збіг цілих слів",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "Настройки безпеки вашого браузера не дозволяють редактору автоматично виконувати операції вирізування. Будь ласка, використовуйте клавіатуру для цього (Ctrl+X).",\r\n
PasteErrorCopy\t: "Настройки безпеки вашого браузера не дозволяють редактору автоматично виконувати операції копіювання. Будь ласка, використовуйте клавіатуру для цього (Ctrl+C).",\r\n
\r\n
PasteAsText\t\t: "Вставити тільки текст",\r\n
PasteFromWord\t: "Вставити з Word",\r\n
\r\n
DlgPasteMsg2\t: "Будь-ласка, вставте з буфера обміну в цю область, користуючись комбінацією клавіш (<STRONG>Ctrl+V</STRONG>) та натисніть <STRONG>OK</STRONG>.",\r\n
DlgPasteSec\t\t: "Редактор не може отримати прямий доступ до буферу обміну у зв\'язку з налаштуваннями вашого браузера. Вам потрібно вставити інформацію повторно в це вікно.",\r\n
DlgPasteIgnoreFont\t\t: "Ігнорувати налаштування шрифтів",\r\n
DlgPasteRemoveStyles\t: "Видалити налаштування стилів",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Автоматичний",\r\n
ColorMoreColors\t: "Кольори...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Властивості документа",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Властивості якоря",\r\n
DlgAnchorName\t\t: "Ім\'я якоря",\r\n
DlgAnchorErrorName\t: "Будь ласка, занесіть ім\'я якоря",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Не має в словнику",\r\n
DlgSpellChangeTo\t\t: "Замінити на",\r\n
DlgSpellBtnIgnore\t\t: "Ігнорувати",\r\n
DlgSpellBtnIgnoreAll\t: "Ігнорувати все",\r\n
DlgSpellBtnReplace\t\t: "Замінити",\r\n
DlgSpellBtnReplaceAll\t: "Замінити все",\r\n
DlgSpellBtnUndo\t\t\t: "Назад",\r\n
DlgSpellNoSuggestions\t: "- Немає припущень -",\r\n
DlgSpellProgress\t\t: "Виконується перевірка орфографії...",\r\n
DlgSpellNoMispell\t\t: "Перевірку орфографії завершено: помилок не знайдено",\r\n
DlgSpellNoChanges\t\t: "Перевірку орфографії завершено: жодне слово не змінено",\r\n
DlgSpellOneChange\t\t: "Перевірку орфографії завершено: змінено одно слово",\r\n
DlgSpellManyChanges\t\t: "Перевірку орфографії завершено: 1% слів змінено",\r\n
\r\n
IeSpellDownload\t\t\t: "Модуль перевірки орфографії не встановлено. Бажаєтн завантажити його зараз?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Текст (Значення)",\r\n
DlgButtonType\t\t: "Тип",\r\n
DlgButtonTypeBtn\t: "Кнопка",\r\n
DlgButtonTypeSbm\t: "Відправити",\r\n
DlgButtonTypeRst\t: "Скинути",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Ім\'я",\r\n
DlgCheckboxValue\t: "Значення",\r\n
DlgCheckboxSelected\t: "Обрана",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Ім\'я",\r\n
DlgFormAction\t: "Дія",\r\n
DlgFormMethod\t: "Метод",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Ім\'я",\r\n
DlgSelectValue\t\t: "Значення",\r\n
DlgSelectSize\t\t: "Розмір",\r\n
DlgSelectLines\t\t: "лінії",\r\n
DlgSelectChkMulti\t: "Дозволити обрання декількох позицій",\r\n
DlgSelectOpAvail\t: "Доступні варіанти",\r\n
DlgSelectOpText\t\t: "Текст",\r\n
DlgSelectOpValue\t: "Значення",\r\n
DlgSelectBtnAdd\t\t: "Добавити",\r\n
DlgSelectBtnModify\t: "Змінити",\r\n
DlgSelectBtnUp\t\t: "Вгору",\r\n
DlgSelectBtnDown\t: "Вниз",\r\n
DlgSelectBtnSetValue : "Встановити як вибране значення",\r\n
DlgSelectBtnDelete\t: "Видалити",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Ім\'я",\r\n
DlgTextareaCols\t: "Колонки",\r\n
DlgTextareaRows\t: "Строки",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Ім\'я",\r\n
DlgTextValue\t\t: "Значення",\r\n
DlgTextCharWidth\t: "Ширина",\r\n
DlgTextMaxChars\t\t: "Макс. кіл-ть символів",\r\n
DlgTextType\t\t\t: "Тип",\r\n
DlgTextTypeText\t\t: "Текст",\r\n
DlgTextTypePass\t\t: "Пароль",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Ім\'я",\r\n
DlgHiddenValue\t: "Значення",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Властивості маркованого списка",\r\n
NumberedListProp\t: "Властивості нумерованного списка",\r\n
DlgLstStart\t\t\t: "Початок",\r\n
DlgLstType\t\t\t: "Тип",\r\n
DlgLstTypeCircle\t: "Коло",\r\n
DlgLstTypeDisc\t\t: "Диск",\r\n
DlgLstTypeSquare\t: "Квадрат",\r\n
DlgLstTypeNumbers\t: "Номери (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Літери нижнього регістра(a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Букви верхнього регістра (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Малі римські літери (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Великі римські літери (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Загальні",\r\n
DlgDocBackTab\t\t: "Заднє тло",\r\n
DlgDocColorsTab\t\t: "Кольори та відступи",\r\n
DlgDocMetaTab\t\t: "Мета дані",\r\n
\r\n
DlgDocPageTitle\t\t: "Заголовок сторінки",\r\n
DlgDocLangDir\t\t: "Напрямок тексту",\r\n
DlgDocLangDirLTR\t: "Зліва на право (LTR)",\r\n
DlgDocLangDirRTL\t: "Зправа на лево (RTL)",\r\n
DlgDocLangCode\t\t: "Код мови",\r\n
DlgDocCharSet\t\t: "Кодування набору символів",\r\n
DlgDocCharSetCE\t\t: "Центрально-європейська",\r\n
DlgDocCharSetCT\t\t: "Китайська традиційна (Big5)",\r\n
DlgDocCharSetCR\t\t: "Кирилиця",\r\n
DlgDocCharSetGR\t\t: "Грецька",\r\n
DlgDocCharSetJP\t\t: "Японська",\r\n
DlgDocCharSetKR\t\t: "Корейська",\r\n
DlgDocCharSetTR\t\t: "Турецька",\r\n
DlgDocCharSetUN\t\t: "Юнікод (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "Західно-европейская",\r\n
DlgDocCharSetOther\t: "Інше кодування набору символів",\r\n
\r\n
DlgDocDocType\t\t: "Заголовок типу документу",\r\n
DlgDocDocTypeOther\t: "Інший заголовок типу документу",\r\n
DlgDocIncXHTML\t\t: "Ввімкнути XHTML оголошення",\r\n
DlgDocBgColor\t\t: "Колір тла",\r\n
DlgDocBgImage\t\t: "URL зображення тла",\r\n
DlgDocBgNoScroll\t: "Тло без прокрутки",\r\n
DlgDocCText\t\t\t: "Текст",\r\n
DlgDocCLink\t\t\t: "Посилання",\r\n
DlgDocCVisited\t\t: "Відвідане посилання",\r\n
DlgDocCActive\t\t: "Активне посилання",\r\n
DlgDocMargins\t\t: "Відступи сторінки",\r\n
DlgDocMaTop\t\t\t: "Верхній",\r\n
DlgDocMaLeft\t\t: "Лівий",\r\n
DlgDocMaRight\t\t: "Правий",\r\n
DlgDocMaBottom\t\t: "Нижній",\r\n
DlgDocMeIndex\t\t: "Ключові слова документа (розділені комами)",\r\n
DlgDocMeDescr\t\t: "Опис документа",\r\n
DlgDocMeAuthor\t\t: "Автор",\r\n
DlgDocMeCopy\t\t: "Авторські права",\r\n
DlgDocPreview\t\t: "Попередній перегляд",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Шаблони",\r\n
DlgTemplatesTitle\t: "Шаблони змісту",\r\n
DlgTemplatesSelMsg\t: "Оберіть, будь ласка, шаблон для відкриття в редакторі<br>(поточний зміст буде втрачено):",\r\n
DlgTemplatesLoading\t: "Завантаження списку шаблонів. Зачекайте, будь ласка...",\r\n
DlgTemplatesNoTpl\t: "(Не визначено жодного шаблону)",\r\n
DlgTemplatesReplace\t: "Замінити поточний вміст",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Про програму",\r\n
DlgAboutBrowserInfoTab\t: "Інформація браузера",\r\n
DlgAboutLicenseTab\t: "Ліцензія",\r\n
DlgAboutVersion\t\t: "Версія",\r\n
DlgAboutInfo\t\t: "Додаткову інформацію дивіться на ",\r\n
\r\n
// Div Dialog\r\n
DlgDivGeneralTab\t: "Загальна",\r\n
DlgDivAdvancedTab\t: "Розширена",\r\n
DlgDivStyle\t\t: "Стиль",\r\n
DlgDivInlineStyle\t: "Inline стиль",\r\n
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
            <value> <int>25884</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
