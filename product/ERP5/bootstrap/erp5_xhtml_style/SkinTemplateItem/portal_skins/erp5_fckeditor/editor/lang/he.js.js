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
            <value> <string>he.js</string> </value>
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
 * Hebrew language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "rtl",\r\n
\r\n
ToolbarCollapse\t\t: "כיווץ סרגל הכלים",\r\n
ToolbarExpand\t\t: "פתיחת סרגל הכלים",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "שמירה",\r\n
NewPage\t\t\t\t: "דף חדש",\r\n
Preview\t\t\t\t: "תצוגה מקדימה",\r\n
Cut\t\t\t\t\t: "גזירה",\r\n
Copy\t\t\t\t: "העתקה",\r\n
Paste\t\t\t\t: "הדבקה",\r\n
PasteText\t\t\t: "הדבקה כטקסט פשוט",\r\n
PasteWord\t\t\t: "הדבקה מ-וורד",\r\n
Print\t\t\t\t: "הדפסה",\r\n
SelectAll\t\t\t: "בחירת הכל",\r\n
RemoveFormat\t\t: "הסרת העיצוב",\r\n
InsertLinkLbl\t\t: "קישור",\r\n
InsertLink\t\t\t: "הוספת/עריכת קישור",\r\n
RemoveLink\t\t\t: "הסרת הקישור",\r\n
VisitLink\t\t\t: "פתח קישור",\r\n
Anchor\t\t\t\t: "הוספת/עריכת נקודת עיגון",\r\n
AnchorDelete\t\t: "הסר נקודת עיגון",\r\n
InsertImageLbl\t\t: "תמונה",\r\n
InsertImage\t\t\t: "הוספת/עריכת תמונה",\r\n
InsertFlashLbl\t\t: "פלאש",\r\n
InsertFlash\t\t\t: "הוסף/ערוך פלאש",\r\n
InsertTableLbl\t\t: "טבלה",\r\n
InsertTable\t\t\t: "הוספת/עריכת טבלה",\r\n
InsertLineLbl\t\t: "קו",\r\n
InsertLine\t\t\t: "הוספת קו אופקי",\r\n
InsertSpecialCharLbl: "תו מיוחד",\r\n
InsertSpecialChar\t: "הוספת תו מיוחד",\r\n
InsertSmileyLbl\t\t: "סמיילי",\r\n
InsertSmiley\t\t: "הוספת סמיילי",\r\n
About\t\t\t\t: "אודות FCKeditor",\r\n
Bold\t\t\t\t: "מודגש",\r\n
Italic\t\t\t\t: "נטוי",\r\n
Underline\t\t\t: "קו תחתון",\r\n
StrikeThrough\t\t: "כתיב מחוק",\r\n
Subscript\t\t\t: "כתיב תחתון",\r\n
Superscript\t\t\t: "כתיב עליון",\r\n
LeftJustify\t\t\t: "יישור לשמאל",\r\n
CenterJustify\t\t: "מרכוז",\r\n
RightJustify\t\t: "יישור לימין",\r\n
BlockJustify\t\t: "יישור לשוליים",\r\n
DecreaseIndent\t\t: "הקטנת אינדנטציה",\r\n
IncreaseIndent\t\t: "הגדלת אינדנטציה",\r\n
Blockquote\t\t\t: "בלוק ציטוט",\r\n
CreateDiv\t\t\t: "צור מיכל(תג)DIV",\r\n
EditDiv\t\t\t\t: "ערוך מיכל (תג)DIV",\r\n
DeleteDiv\t\t\t: "הסר מיכל(תג) DIV",\r\n
Undo\t\t\t\t: "ביטול צעד אחרון",\r\n
Redo\t\t\t\t: "חזרה על צעד אחרון",\r\n
NumberedListLbl\t\t: "רשימה ממוספרת",\r\n
NumberedList\t\t: "הוספת/הסרת רשימה ממוספרת",\r\n
BulletedListLbl\t\t: "רשימת נקודות",\r\n
BulletedList\t\t: "הוספת/הסרת רשימת נקודות",\r\n
ShowTableBorders\t: "הצגת מסגרת הטבלה",\r\n
ShowDetails\t\t\t: "הצגת פרטים",\r\n
Style\t\t\t\t: "סגנון",\r\n
FontFormat\t\t\t: "עיצוב",\r\n
Font\t\t\t\t: "גופן",\r\n
FontSize\t\t\t: "גודל",\r\n
TextColor\t\t\t: "צבע טקסט",\r\n
BGColor\t\t\t\t: "צבע רקע",\r\n
Source\t\t\t\t: "מקור",\r\n
Find\t\t\t\t: "חיפוש",\r\n
Replace\t\t\t\t: "החלפה",\r\n
SpellCheck\t\t\t: "בדיקת איות",\r\n
UniversalKeyboard\t: "מקלדת אוניברסלית",\r\n
PageBreakLbl\t\t: "שבירת דף",\r\n
PageBreak\t\t\t: "הוסף שבירת דף",\r\n
\r\n
Form\t\t\t: "טופס",\r\n
Checkbox\t\t: "תיבת סימון",\r\n
RadioButton\t\t: "לחצן אפשרויות",\r\n
TextField\t\t: "שדה טקסט",\r\n
Textarea\t\t: "איזור טקסט",\r\n
HiddenField\t\t: "שדה חבוי",\r\n
Button\t\t\t: "כפתור",\r\n
SelectionField\t: "שדה בחירה",\r\n
ImageButton\t\t: "כפתור תמונה",\r\n
\r\n
FitWindow\t\t: "הגדל את גודל העורך",\r\n
ShowBlocks\t\t: "הצג בלוקים",\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "עריכת קישור",\r\n
CellCM\t\t\t\t: "תא",\r\n
RowCM\t\t\t\t: "שורה",\r\n
ColumnCM\t\t\t: "עמודה",\r\n
InsertRowAfter\t\t: "הוסף שורה אחרי",\r\n
InsertRowBefore\t\t: "הוסף שורה לפני",\r\n
DeleteRows\t\t\t: "מחיקת שורות",\r\n
InsertColumnAfter\t: "הוסף עמודה אחרי",\r\n
InsertColumnBefore\t: "הוסף עמודה לפני",\r\n
DeleteColumns\t\t: "מחיקת עמודות",\r\n
InsertCellAfter\t\t: "הוסף תא אחרי",\r\n
InsertCellBefore\t: "הוסף תא אחרי",\r\n
DeleteCells\t\t\t: "מחיקת תאים",\r\n
MergeCells\t\t\t: "מיזוג תאים",\r\n
MergeRight\t\t\t: "מזג ימינה",\r\n
MergeDown\t\t\t: "מזג למטה",\r\n
HorizontalSplitCell\t: "פצל תא אופקית",\r\n
VerticalSplitCell\t: "פצל תא אנכית",\r\n
TableDelete\t\t\t: "מחק טבלה",\r\n
CellProperties\t\t: "תכונות התא",\r\n
TableProperties\t\t: "תכונות הטבלה",\r\n
ImageProperties\t\t: "תכונות התמונה",\r\n
FlashProperties\t\t: "מאפייני פלאש",\r\n
\r\n
AnchorProp\t\t\t: "מאפייני נקודת עיגון",\r\n
ButtonProp\t\t\t: "מאפייני כפתור",\r\n
CheckboxProp\t\t: "מאפייני תיבת סימון",\r\n
HiddenFieldProp\t\t: "מאפיני שדה חבוי",\r\n
RadioButtonProp\t\t: "מאפייני לחצן אפשרויות",\r\n
ImageButtonProp\t\t: "מאפיני כפתור תמונה",\r\n
TextFieldProp\t\t: "מאפייני שדה טקסט",\r\n
SelectionFieldProp\t: "מאפייני שדה בחירה",\r\n
TextareaProp\t\t: "מאפיני איזור טקסט",\r\n
FormProp\t\t\t: "מאפיני טופס",\r\n
\r\n
FontFormats\t\t\t: "נורמלי;קוד;כתובת;כותרת;כותרת 2;כותרת 3;כותרת 4;כותרת 5;כותרת 6",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "מעבד XHTML, נא להמתין...",\r\n
Done\t\t\t\t: "המשימה הושלמה",\r\n
PasteWordConfirm\t: "נראה הטקסט שבכוונתך להדביק מקורו בקובץ וורד. האם ברצונך לנקות אותו טרם ההדבקה?",\r\n
NotCompatiblePaste\t: "פעולה זו זמינה לדפדפן אינטרנט אקספלורר מגירסא 5.5 ומעלה. האם להמשיך בהדבקה ללא הניקוי?",\r\n
UnknownToolbarItem\t: "פריט לא ידוע בסרגל הכלים \\"%1\\"",\r\n
UnknownCommand\t\t: "שם פעולה לא ידוע \\"%1\\"",\r\n
NotImplemented\t\t: "הפקודה לא מיושמת",\r\n
UnknownToolbarSet\t: "ערכת סרגל הכלים \\"%1\\" לא קיימת",\r\n
NoActiveX\t\t\t: "הגדרות אבטחה של הדפדפן עלולות לגביל את אפשרויות העריכה.יש לאפשר את האופציה \\"הרץ פקדים פעילים ותוספות\\". תוכל לחוות טעויות וחיווים של אפשרויות שחסרים.",\r\n
BrowseServerBlocked : "לא ניתן לגשת לדפדפן משאבים.אנא וודא שחוסם חלונות הקופצים לא פעיל.",\r\n
DialogBlocked\t\t: "לא היה ניתן לפתוח חלון דיאלוג. אנא וודא שחוסם חלונות קופצים לא פעיל.",\r\n
VisitLinkBlocked\t: "לא ניתן לפתוח חלון חדש.נא לוודא שחוסמי החלונות הקופצים לא פעילים.",\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "אישור",\r\n
DlgBtnCancel\t\t: "ביטול",\r\n
DlgBtnClose\t\t\t: "סגירה",\r\n
DlgBtnBrowseServer\t: "סייר השרת",\r\n
DlgAdvancedTag\t\t: "אפשרויות מתקדמות",\r\n
DlgOpOther\t\t\t: "<אחר>",\r\n
DlgInfoTab\t\t\t: "מידע",\r\n
DlgAlertUrl\t\t\t: "אנא הזן URL",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<לא נקבע>",\r\n
DlgGenId\t\t\t: "זיהוי (Id)",\r\n
DlgGenLangDir\t\t: "כיוון שפה",\r\n
DlgGenLangDirLtr\t: "שמאל לימין (LTR)",\r\n
DlgGenLangDirRtl\t: "ימין לשמאל (RTL)",\r\n
DlgGenLangCode\t\t: "קוד שפה",\r\n
DlgGenAccessKey\t\t: "מקש גישה",\r\n
DlgGenName\t\t\t: "שם",\r\n
DlgGenTabIndex\t\t: "מספר טאב",\r\n
DlgGenLongDescr\t\t: "קישור לתיאור מפורט",\r\n
DlgGenClass\t\t\t: "גיליונות עיצוב קבוצות",\r\n
DlgGenTitle\t\t\t: "כותרת מוצעת",\r\n
DlgGenContType\t\t: "Content Type מוצע",\r\n
DlgGenLinkCharset\t: "קידוד המשאב המקושר",\r\n
DlgGenStyle\t\t\t: "סגנון",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "תכונות התמונה",\r\n
DlgImgInfoTab\t\t: "מידע על התמונה",\r\n
DlgImgBtnUpload\t\t: "שליחה לשרת",\r\n
DlgImgURL\t\t\t: "כתובת (URL)",\r\n
DlgImgUpload\t\t: "העלאה",\r\n
DlgImgAlt\t\t\t: "טקסט חלופי",\r\n
DlgImgWidth\t\t\t: "רוחב",\r\n
DlgImgHeight\t\t: "גובה",\r\n
DlgImgLockRatio\t\t: "נעילת היחס",\r\n
DlgBtnResetSize\t\t: "איפוס הגודל",\r\n
DlgImgBorder\t\t: "מסגרת",\r\n
DlgImgHSpace\t\t: "מרווח אופקי",\r\n
DlgImgVSpace\t\t: "מרווח אנכי",\r\n
DlgImgAlign\t\t\t: "יישור",\r\n
DlgImgAlignLeft\t\t: "לשמאל",\r\n
DlgImgAlignAbsBottom: "לתחתית האבסולוטית",\r\n
DlgImgAlignAbsMiddle: "מרכוז אבסולוטי",\r\n
DlgImgAlignBaseline\t: "לקו התחתית",\r\n
DlgImgAlignBottom\t: "לתחתית",\r\n
DlgImgAlignMiddle\t: "לאמצע",\r\n
DlgImgAlignRight\t: "לימין",\r\n
DlgImgAlignTextTop\t: "לראש הטקסט",\r\n
DlgImgAlignTop\t\t: "למעלה",\r\n
DlgImgPreview\t\t: "תצוגה מקדימה",\r\n
DlgImgAlertUrl\t\t: "נא להקליד את כתובת התמונה",\r\n
DlgImgLinkTab\t\t: "קישור",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "מאפיני פלאש",\r\n
DlgFlashChkPlay\t\t: "נגן אוטומטי",\r\n
DlgFlashChkLoop\t\t: "לולאה",\r\n
DlgFlashChkMenu\t\t: "אפשר תפריט פלאש",\r\n
DlgFlashScale\t\t: "גודל",\r\n
DlgFlashScaleAll\t: "הצג הכל",\r\n
DlgFlashScaleNoBorder\t: "ללא גבולות",\r\n
DlgFlashScaleFit\t: "התאמה מושלמת",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "קישור",\r\n
DlgLnkInfoTab\t\t: "מידע על הקישור",\r\n
DlgLnkTargetTab\t\t: "מטרה",\r\n
\r\n
DlgLnkType\t\t\t: "סוג קישור",\r\n
DlgLnkTypeURL\t\t: "כתובת (URL)",\r\n
DlgLnkTypeAnchor\t: "עוגן בעמוד זה",\r\n
DlgLnkTypeEMail\t\t: "דוא\'\'ל",\r\n
DlgLnkProto\t\t\t: "פרוטוקול",\r\n
DlgLnkProtoOther\t: "<אחר>",\r\n
DlgLnkURL\t\t\t: "כתובת (URL)",\r\n
DlgLnkAnchorSel\t\t: "בחירת עוגן",\r\n
DlgLnkAnchorByName\t: "עפ\'\'י שם העוגן",\r\n
DlgLnkAnchorById\t: "עפ\'\'י זיהוי (Id) הרכיב",\r\n
DlgLnkNoAnchors\t\t: "(אין עוגנים זמינים בדף)",\r\n
DlgLnkEMail\t\t\t: "כתובת הדוא\'\'ל",\r\n
DlgLnkEMailSubject\t: "נושא ההודעה",\r\n
DlgLnkEMailBody\t\t: "גוף ההודעה",\r\n
DlgLnkUpload\t\t: "העלאה",\r\n
DlgLnkBtnUpload\t\t: "שליחה לשרת",\r\n
\r\n
DlgLnkTarget\t\t: "מטרה",\r\n
DlgLnkTargetFrame\t: "<מסגרת>",\r\n
DlgLnkTargetPopup\t: "<חלון קופץ>",\r\n
DlgLnkTargetBlank\t: "חלון חדש (_blank)",\r\n
DlgLnkTargetParent\t: "חלון האב (_parent)",\r\n
DlgLnkTargetSelf\t: "באותו החלון (_self)",\r\n
DlgLnkTargetTop\t\t: "חלון ראשי (_top)",\r\n
DlgLnkTargetFrameName\t: "שם מסגרת היעד",\r\n
DlgLnkPopWinName\t: "שם החלון הקופץ",\r\n
DlgLnkPopWinFeat\t: "תכונות החלון הקופץ",\r\n
DlgLnkPopResize\t\t: "בעל גודל ניתן לשינוי",\r\n
DlgLnkPopLocation\t: "סרגל כתובת",\r\n
DlgLnkPopMenu\t\t: "סרגל תפריט",\r\n
DlgLnkPopScroll\t\t: "ניתן לגלילה",\r\n
DlgLnkPopStatus\t\t: "סרגל חיווי",\r\n
DlgLnkPopToolbar\t: "סרגל הכלים",\r\n
DlgLnkPopFullScrn\t: "מסך מלא (IE)",\r\n
DlgLnkPopDependent\t: "תלוי (Netscape)",\r\n
DlgLnkPopWidth\t\t: "רוחב",\r\n
DlgLnkPopHeight\t\t: "גובה",\r\n
DlgLnkPopLeft\t\t: "מיקום צד שמאל",\r\n
DlgLnkPopTop\t\t: "מיקום צד עליון",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "נא להקליד את כתובת הקישור (URL)",\r\n
DlnLnkMsgNoEMail\t: "נא להקליד את כתובת הדוא\'\'ל",\r\n
DlnLnkMsgNoAnchor\t: "נא לבחור עוגן במסמך",\r\n
DlnLnkMsgInvPopName\t: "שם החלון הקופץ חייב להתחיל באותיות ואסור לכלול רווחים",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "בחירת צבע",\r\n
DlgColorBtnClear\t: "איפוס",\r\n
DlgColorHighlight\t: "נוכחי",\r\n
DlgColorSelected\t: "נבחר",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "הוספת סמיילי",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "בחירת תו מיוחד",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "תכונות טבלה",\r\n
DlgTableRows\t\t: "שורות",\r\n
DlgTableColumns\t\t: "עמודות",\r\n
DlgTableBorder\t\t: "גודל מסגרת",\r\n
DlgTableAlign\t\t: "יישור",\r\n
DlgTableAlignNotSet\t: "<לא נקבע>",\r\n
DlgTableAlignLeft\t: "שמאל",\r\n
DlgTableAlignCenter\t: "מרכז",\r\n
DlgTableAlignRight\t: "ימין",\r\n
DlgTableWidth\t\t: "רוחב",\r\n
DlgTableWidthPx\t\t: "פיקסלים",\r\n
DlgTableWidthPc\t\t: "אחוז",\r\n
DlgTableHeight\t\t: "גובה",\r\n
DlgTableCellSpace\t: "מרווח תא",\r\n
DlgTableCellPad\t\t: "ריפוד תא",\r\n
DlgTableCaption\t\t: "כיתוב",\r\n
DlgTableSummary\t\t: "סיכום",\r\n
DlgTableHeaders\t\t: "כותרות",\r\n
DlgTableHeadersNone\t\t: "אין",\r\n
DlgTableHeadersColumn\t: "עמודה ראשונה",\r\n
DlgTableHeadersRow\t\t: "שורה ראשונה",\r\n
DlgTableHeadersBoth\t\t: "שניהם",\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "תכונות תא",\r\n
DlgCellWidth\t\t: "רוחב",\r\n
DlgCellWidthPx\t\t: "פיקסלים",\r\n
DlgCellWidthPc\t\t: "אחוז",\r\n
DlgCellHeight\t\t: "גובה",\r\n
DlgCellWordWrap\t\t: "גלילת שורות",\r\n
DlgCellWordWrapNotSet\t: "<לא נקבע>",\r\n
DlgCellWordWrapYes\t: "כן",\r\n
DlgCellWordWrapNo\t: "לא",\r\n
DlgCellHorAlign\t\t: "יישור אופקי",\r\n
DlgCellHorAlignNotSet\t: "<לא נקבע>",\r\n
DlgCellHorAlignLeft\t: "שמאל",\r\n
DlgCellHorAlignCenter\t: "מרכז",\r\n
DlgCellHorAlignRight: "ימין",\r\n
DlgCellVerAlign\t\t: "יישור אנכי",\r\n
DlgCellVerAlignNotSet\t: "<לא נקבע>",\r\n
DlgCellVerAlignTop\t: "למעלה",\r\n
DlgCellVerAlignMiddle\t: "לאמצע",\r\n
DlgCellVerAlignBottom\t: "לתחתית",\r\n
DlgCellVerAlignBaseline\t: "קו תחתית",\r\n
DlgCellType\t\t: "סוג תא",\r\n
DlgCellTypeData\t\t: "סוג",\r\n
DlgCellTypeHeader\t: "כותרת",\r\n
DlgCellRowSpan\t\t: "טווח שורות",\r\n
DlgCellCollSpan\t\t: "טווח עמודות",\r\n
DlgCellBackColor\t: "צבע רקע",\r\n
DlgCellBorderColor\t: "צבע מסגרת",\r\n
DlgCellBtnSelect\t: "בחירה...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "חפש והחלף",\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "חיפוש",\r\n
DlgFindFindBtn\t\t: "חיפוש",\r\n
DlgFindNotFoundMsg\t: "הטקסט המבוקש לא נמצא.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "החלפה",\r\n
DlgReplaceFindLbl\t\t: "חיפוש מחרוזת:",\r\n
DlgReplaceReplaceLbl\t: "החלפה במחרוזת:",\r\n
DlgReplaceCaseChk\t\t: "התאמת סוג אותיות (Case)",\r\n
DlgReplaceReplaceBtn\t: "החלפה",\r\n
DlgReplaceReplAllBtn\t: "החלפה בכל העמוד",\r\n
DlgReplaceWordChk\t\t: "התאמה למילה המלאה",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "הגדרות האבטחה בדפדפן שלך לא מאפשרות לעורך לבצע פעולות גזירה  אוטומטיות. יש להשתמש במקלדת לשם כך (Ctrl+X).",\r\n
PasteErrorCopy\t: "הגדרות האבטחה בדפדפן שלך לא מאפשרות לעורך לבצע פעולות העתקה אוטומטיות. יש להשתמש במקלדת לשם כך (Ctrl+C).",\r\n
\r\n
PasteAsText\t\t: "הדבקה כטקסט פשוט",\r\n
PasteFromWord\t: "הדבקה מ-וורד",\r\n
\r\n
DlgPasteMsg2\t: "אנא הדבק בתוך הקופסה באמצעות  (<STRONG>Ctrl+V</STRONG>) ולחץ על  <STRONG>אישור</STRONG>.",\r\n
DlgPasteSec\t\t: "עקב הגדרות אבטחה בדפדפן, לא ניתן לגשת אל לוח הגזירים (clipboard) בצורה ישירה.אנא בצע הדבק שוב בחלון זה.",\r\n
DlgPasteIgnoreFont\t\t: "התעלם מהגדרות סוג פונט",\r\n
DlgPasteRemoveStyles\t: "הסר הגדרות סגנון",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "אוטומטי",\r\n
ColorMoreColors\t: "צבעים נוספים...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "מאפיני מסמך",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "מאפיני נקודת עיגון",\r\n
DlgAnchorName\t\t: "שם לנקודת עיגון",\r\n
DlgAnchorErrorName\t: "אנא הזן שם לנקודת עיגון",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "לא נמצא במילון",\r\n
DlgSpellChangeTo\t\t: "שנה ל",\r\n
DlgSpellBtnIgnore\t\t: "התעלם",\r\n
DlgSpellBtnIgnoreAll\t: "התעלם מהכל",\r\n
DlgSpellBtnReplace\t\t: "החלף",\r\n
DlgSpellBtnReplaceAll\t: "החלף הכל",\r\n
DlgSpellBtnUndo\t\t\t: "החזר",\r\n
DlgSpellNoSuggestions\t: "- אין הצעות -",\r\n
DlgSpellProgress\t\t: "בדיקות איות בתהליך ....",\r\n
DlgSpellNoMispell\t\t: "בדיקות איות הסתיימה: לא נמצאו שגיעות כתיב",\r\n
DlgSpellNoChanges\t\t: "בדיקות איות הסתיימה: לא שונתה אף מילה",\r\n
DlgSpellOneChange\t\t: "בדיקות איות הסתיימה: שונתה מילה אחת",\r\n
DlgSpellManyChanges\t\t: "בדיקות איות הסתיימה: %1 מילים שונו",\r\n
\r\n
IeSpellDownload\t\t\t: "בודק האיות לא מותקן, האם אתה מעוניין להוריד?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "טקסט (ערך)",\r\n
DlgButtonType\t\t: "סוג",\r\n
DlgButtonTypeBtn\t: "כפתור",\r\n
DlgButtonTypeSbm\t: "שלח",\r\n
DlgButtonTypeRst\t: "אפס",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "שם",\r\n
DlgCheckboxValue\t: "ערך",\r\n
DlgCheckboxSelected\t: "בחור",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "שם",\r\n
DlgFormAction\t: "שלח אל",\r\n
DlgFormMethod\t: "סוג שליחה",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "שם",\r\n
DlgSelectValue\t\t: "ערך",\r\n
DlgSelectSize\t\t: "גודל",\r\n
DlgSelectLines\t\t: "שורות",\r\n
DlgSelectChkMulti\t: "אפשר בחירות מרובות",\r\n
DlgSelectOpAvail\t: "אפשרויות זמינות",\r\n
DlgSelectOpText\t\t: "טקסט",\r\n
DlgSelectOpValue\t: "ערך",\r\n
DlgSelectBtnAdd\t\t: "הוסף",\r\n
DlgSelectBtnModify\t: "שנה",\r\n
DlgSelectBtnUp\t\t: "למעלה",\r\n
DlgSelectBtnDown\t: "למטה",\r\n
DlgSelectBtnSetValue : "קבע כברירת מחדל",\r\n
DlgSelectBtnDelete\t: "מחק",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "שם",\r\n
DlgTextareaCols\t: "עמודות",\r\n
DlgTextareaRows\t: "שורות",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "שם",\r\n
DlgTextValue\t\t: "ערך",\r\n
DlgTextCharWidth\t: "רוחב באותיות",\r\n
DlgTextMaxChars\t\t: "מקסימות אותיות",\r\n
DlgTextType\t\t\t: "סוג",\r\n
DlgTextTypeText\t\t: "טקסט",\r\n
DlgTextTypePass\t\t: "סיסמה",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "שם",\r\n
DlgHiddenValue\t: "ערך",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "מאפייני רשימה",\r\n
NumberedListProp\t: "מאפייני רשימה ממוספרת",\r\n
DlgLstStart\t\t\t: "התחלה",\r\n
DlgLstType\t\t\t: "סוג",\r\n
DlgLstTypeCircle\t: "עיגול",\r\n
DlgLstTypeDisc\t\t: "דיסק",\r\n
DlgLstTypeSquare\t: "מרובע",\r\n
DlgLstTypeNumbers\t: "מספרים (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "אותיות קטנות (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "אותיות גדולות (A, B, C)",\r\n
DlgLstTypeSRoman\t: "ספרות רומאיות קטנות (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "ספרות רומאיות גדולות (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "כללי",\r\n
DlgDocBackTab\t\t: "רקע",\r\n
DlgDocColorsTab\t\t: "צבעים וגבולות",\r\n
DlgDocMetaTab\t\t: "נתוני META",\r\n
\r\n
DlgDocPageTitle\t\t: "כותרת דף",\r\n
DlgDocLangDir\t\t: "כיוון שפה",\r\n
DlgDocLangDirLTR\t: "שמאל לימין (LTR)",\r\n
DlgDocLangDirRTL\t: "ימין לשמאל (RTL)",\r\n
DlgDocLangCode\t\t: "קוד שפה",\r\n
DlgDocCharSet\t\t: "קידוד אותיות",\r\n
DlgDocCharSetCE\t\t: "מרכז אירופה",\r\n
DlgDocCharSetCT\t\t: "סיני מסורתי (Big5)",\r\n
DlgDocCharSetCR\t\t: "קירילי",\r\n
DlgDocCharSetGR\t\t: "יוונית",\r\n
DlgDocCharSetJP\t\t: "יפנית",\r\n
DlgDocCharSetKR\t\t: "קוראנית",\r\n
DlgDocCharSetTR\t\t: "טורקית",\r\n
DlgDocCharSetUN\t\t: "יוני קוד (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "מערב אירופה",\r\n
DlgDocCharSetOther\t: "קידוד אותיות אחר",\r\n
\r\n
DlgDocDocType\t\t: "הגדרות סוג מסמך",\r\n
DlgDocDocTypeOther\t: "הגדרות סוג מסמך אחרות",\r\n
DlgDocIncXHTML\t\t: "כלול הגדרות XHTML",\r\n
DlgDocBgColor\t\t: "צבע רקע",\r\n
DlgDocBgImage\t\t: "URL לתמונת רקע",\r\n
DlgDocBgNoScroll\t: "רגע ללא גלילה",\r\n
DlgDocCText\t\t\t: "טקסט",\r\n
DlgDocCLink\t\t\t: "קישור",\r\n
DlgDocCVisited\t\t: "קישור שבוקר",\r\n
DlgDocCActive\t\t: " קישור פעיל",\r\n
DlgDocMargins\t\t: "גבולות דף",\r\n
DlgDocMaTop\t\t\t: "למעלה",\r\n
DlgDocMaLeft\t\t: "שמאלה",\r\n
DlgDocMaRight\t\t: "ימינה",\r\n
DlgDocMaBottom\t\t: "למטה",\r\n
DlgDocMeIndex\t\t: "מפתח עניינים של המסמך )מופרד בפסיק(",\r\n
DlgDocMeDescr\t\t: "תאור מסמך",\r\n
DlgDocMeAuthor\t\t: "מחבר",\r\n
DlgDocMeCopy\t\t: "זכויות יוצרים",\r\n
DlgDocPreview\t\t: "תצוגה מקדימה",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "תבניות",\r\n
DlgTemplatesTitle\t: "תביות תוכן",\r\n
DlgTemplatesSelMsg\t: "אנא בחר תבנית לפתיחה בעורך <BR>התוכן המקורי ימחק:",\r\n
DlgTemplatesLoading\t: "מעלה רשימת תבניות אנא המתן",\r\n
DlgTemplatesNoTpl\t: "(לא הוגדרו תבניות)",\r\n
DlgTemplatesReplace\t: "החלפת תוכן ממשי",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "אודות",\r\n
DlgAboutBrowserInfoTab\t: "גירסת דפדפן",\r\n
DlgAboutLicenseTab\t: "רשיון",\r\n
DlgAboutVersion\t\t: "גירסא",\r\n
DlgAboutInfo\t\t: "מידע נוסף ניתן למצוא כאן:",\r\n
\r\n
// Div Dialog\r\n
DlgDivGeneralTab\t: "כללי",\r\n
DlgDivAdvancedTab\t: "מתקדם",\r\n
DlgDivStyle\t\t: "סגנון",\r\n
DlgDivInlineStyle\t: "סגנון בתוך השורה",\r\n
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
            <value> <int>21397</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
