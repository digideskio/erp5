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
            <value> <string>zh.js</string> </value>
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
 * Chinese Traditional language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "隱藏面板",\r\n
ToolbarExpand\t\t: "顯示面板",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "儲存",\r\n
NewPage\t\t\t\t: "開新檔案",\r\n
Preview\t\t\t\t: "預覽",\r\n
Cut\t\t\t\t\t: "剪下",\r\n
Copy\t\t\t\t: "複製",\r\n
Paste\t\t\t\t: "貼上",\r\n
PasteText\t\t\t: "貼為純文字格式",\r\n
PasteWord\t\t\t: "自 Word 貼上",\r\n
Print\t\t\t\t: "列印",\r\n
SelectAll\t\t\t: "全選",\r\n
RemoveFormat\t\t: "清除格式",\r\n
InsertLinkLbl\t\t: "超連結",\r\n
InsertLink\t\t\t: "插入/編輯超連結",\r\n
RemoveLink\t\t\t: "移除超連結",\r\n
VisitLink\t\t\t: "開啟超連結",\r\n
Anchor\t\t\t\t: "插入/編輯錨點",\r\n
AnchorDelete\t\t: "移除錨點",\r\n
InsertImageLbl\t\t: "影像",\r\n
InsertImage\t\t\t: "插入/編輯影像",\r\n
InsertFlashLbl\t\t: "Flash",\r\n
InsertFlash\t\t\t: "插入/編輯 Flash",\r\n
InsertTableLbl\t\t: "表格",\r\n
InsertTable\t\t\t: "插入/編輯表格",\r\n
InsertLineLbl\t\t: "水平線",\r\n
InsertLine\t\t\t: "插入水平線",\r\n
InsertSpecialCharLbl: "特殊符號",\r\n
InsertSpecialChar\t: "插入特殊符號",\r\n
InsertSmileyLbl\t\t: "表情符號",\r\n
InsertSmiley\t\t: "插入表情符號",\r\n
About\t\t\t\t: "關於 FCKeditor",\r\n
Bold\t\t\t\t: "粗體",\r\n
Italic\t\t\t\t: "斜體",\r\n
Underline\t\t\t: "底線",\r\n
StrikeThrough\t\t: "刪除線",\r\n
Subscript\t\t\t: "下標",\r\n
Superscript\t\t\t: "上標",\r\n
LeftJustify\t\t\t: "靠左對齊",\r\n
CenterJustify\t\t: "置中",\r\n
RightJustify\t\t: "靠右對齊",\r\n
BlockJustify\t\t: "左右對齊",\r\n
DecreaseIndent\t\t: "減少縮排",\r\n
IncreaseIndent\t\t: "增加縮排",\r\n
Blockquote\t\t\t: "引用文字",\r\n
CreateDiv\t\t\t: "新增 Div 標籤",\r\n
EditDiv\t\t\t\t: "變更 Div 標籤",\r\n
DeleteDiv\t\t\t: "移除 Div 標籤",\r\n
Undo\t\t\t\t: "復原",\r\n
Redo\t\t\t\t: "重複",\r\n
NumberedListLbl\t\t: "編號清單",\r\n
NumberedList\t\t: "插入/移除編號清單",\r\n
BulletedListLbl\t\t: "項目清單",\r\n
BulletedList\t\t: "插入/移除項目清單",\r\n
ShowTableBorders\t: "顯示表格邊框",\r\n
ShowDetails\t\t\t: "顯示詳細資料",\r\n
Style\t\t\t\t: "樣式",\r\n
FontFormat\t\t\t: "格式",\r\n
Font\t\t\t\t: "字體",\r\n
FontSize\t\t\t: "大小",\r\n
TextColor\t\t\t: "文字顏色",\r\n
BGColor\t\t\t\t: "背景顏色",\r\n
Source\t\t\t\t: "原始碼",\r\n
Find\t\t\t\t: "尋找",\r\n
Replace\t\t\t\t: "取代",\r\n
SpellCheck\t\t\t: "拼字檢查",\r\n
UniversalKeyboard\t: "萬國鍵盤",\r\n
PageBreakLbl\t\t: "分頁符號",\r\n
PageBreak\t\t\t: "插入分頁符號",\r\n
\r\n
Form\t\t\t: "表單",\r\n
Checkbox\t\t: "核取方塊",\r\n
RadioButton\t\t: "選項按鈕",\r\n
TextField\t\t: "文字方塊",\r\n
Textarea\t\t: "文字區域",\r\n
HiddenField\t\t: "隱藏欄位",\r\n
Button\t\t\t: "按鈕",\r\n
SelectionField\t: "清單/選單",\r\n
ImageButton\t\t: "影像按鈕",\r\n
\r\n
FitWindow\t\t: "編輯器最大化",\r\n
ShowBlocks\t\t: "顯示區塊",\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "編輯超連結",\r\n
CellCM\t\t\t\t: "儲存格",\r\n
RowCM\t\t\t\t: "列",\r\n
ColumnCM\t\t\t: "欄",\r\n
InsertRowAfter\t\t: "向下插入列",\r\n
InsertRowBefore\t\t: "向上插入列",\r\n
DeleteRows\t\t\t: "刪除列",\r\n
InsertColumnAfter\t: "向右插入欄",\r\n
InsertColumnBefore\t: "向左插入欄",\r\n
DeleteColumns\t\t: "刪除欄",\r\n
InsertCellAfter\t\t: "向右插入儲存格",\r\n
InsertCellBefore\t: "向左插入儲存格",\r\n
DeleteCells\t\t\t: "刪除儲存格",\r\n
MergeCells\t\t\t: "合併儲存格",\r\n
MergeRight\t\t\t: "向右合併儲存格",\r\n
MergeDown\t\t\t: "向下合併儲存格",\r\n
HorizontalSplitCell\t: "橫向分割儲存格",\r\n
VerticalSplitCell\t: "縱向分割儲存格",\r\n
TableDelete\t\t\t: "刪除表格",\r\n
CellProperties\t\t: "儲存格屬性",\r\n
TableProperties\t\t: "表格屬性",\r\n
ImageProperties\t\t: "影像屬性",\r\n
FlashProperties\t\t: "Flash 屬性",\r\n
\r\n
AnchorProp\t\t\t: "錨點屬性",\r\n
ButtonProp\t\t\t: "按鈕屬性",\r\n
CheckboxProp\t\t: "核取方塊屬性",\r\n
HiddenFieldProp\t\t: "隱藏欄位屬性",\r\n
RadioButtonProp\t\t: "選項按鈕屬性",\r\n
ImageButtonProp\t\t: "影像按鈕屬性",\r\n
TextFieldProp\t\t: "文字方塊屬性",\r\n
SelectionFieldProp\t: "清單/選單屬性",\r\n
TextareaProp\t\t: "文字區域屬性",\r\n
FormProp\t\t\t: "表單屬性",\r\n
\r\n
FontFormats\t\t\t: "一般;已格式化;位址;標題 1;標題 2;標題 3;標題 4;標題 5;標題 6;一般 (DIV)",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "處理 XHTML 中，請稍候…",\r\n
Done\t\t\t\t: "完成",\r\n
PasteWordConfirm\t: "您想貼上的文字似乎是自 Word 複製而來，請問您是否要先清除 Word 的格式後再行貼上？",\r\n
NotCompatiblePaste\t: "此指令僅在 Internet Explorer 5.5 或以上的版本有效。請問您是否同意不清除格式即貼上？",\r\n
UnknownToolbarItem\t: "未知工具列項目 \\"%1\\"",\r\n
UnknownCommand\t\t: "未知指令名稱 \\"%1\\"",\r\n
NotImplemented\t\t: "尚未安裝此指令",\r\n
UnknownToolbarSet\t: "工具列設定 \\"%1\\" 不存在",\r\n
NoActiveX\t\t\t: "瀏覽器的安全性設定限制了本編輯器的某些功能。您必須啟用安全性設定中的「執行ActiveX控制項與外掛程式」項目，否則本編輯器將會出現錯誤並缺少某些功能",\r\n
BrowseServerBlocked : "無法開啟資源瀏覽器，請確定所有快顯視窗封鎖程式是否關閉",\r\n
DialogBlocked\t\t: "無法開啟對話視窗，請確定所有快顯視窗封鎖程式是否關閉",\r\n
VisitLinkBlocked\t: "無法開啟新視窗，請確定所有快顯視窗封鎖程式是否關閉",\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "確定",\r\n
DlgBtnCancel\t\t: "取消",\r\n
DlgBtnClose\t\t\t: "關閉",\r\n
DlgBtnBrowseServer\t: "瀏覽伺服器端",\r\n
DlgAdvancedTag\t\t: "進階",\r\n
DlgOpOther\t\t\t: "<其他>",\r\n
DlgInfoTab\t\t\t: "資訊",\r\n
DlgAlertUrl\t\t\t: "請插入 URL",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<尚未設定>",\r\n
DlgGenId\t\t\t: "ID",\r\n
DlgGenLangDir\t\t: "語言方向",\r\n
DlgGenLangDirLtr\t: "由左而右 (LTR)",\r\n
DlgGenLangDirRtl\t: "由右而左 (RTL)",\r\n
DlgGenLangCode\t\t: "語言代碼",\r\n
DlgGenAccessKey\t\t: "存取鍵",\r\n
DlgGenName\t\t\t: "名稱",\r\n
DlgGenTabIndex\t\t: "定位順序",\r\n
DlgGenLongDescr\t\t: "詳細 URL",\r\n
DlgGenClass\t\t\t: "樣式表類別",\r\n
DlgGenTitle\t\t\t: "標題",\r\n
DlgGenContType\t\t: "內容類型",\r\n
DlgGenLinkCharset\t: "連結資源之編碼",\r\n
DlgGenStyle\t\t\t: "樣式",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "影像屬性",\r\n
DlgImgInfoTab\t\t: "影像資訊",\r\n
DlgImgBtnUpload\t\t: "上傳至伺服器",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "上傳",\r\n
DlgImgAlt\t\t\t: "替代文字",\r\n
DlgImgWidth\t\t\t: "寬度",\r\n
DlgImgHeight\t\t: "高度",\r\n
DlgImgLockRatio\t\t: "等比例",\r\n
DlgBtnResetSize\t\t: "重設為原大小",\r\n
DlgImgBorder\t\t: "邊框",\r\n
DlgImgHSpace\t\t: "水平距離",\r\n
DlgImgVSpace\t\t: "垂直距離",\r\n
DlgImgAlign\t\t\t: "對齊",\r\n
DlgImgAlignLeft\t\t: "靠左對齊",\r\n
DlgImgAlignAbsBottom: "絕對下方",\r\n
DlgImgAlignAbsMiddle: "絕對中間",\r\n
DlgImgAlignBaseline\t: "基準線",\r\n
DlgImgAlignBottom\t: "靠下對齊",\r\n
DlgImgAlignMiddle\t: "置中對齊",\r\n
DlgImgAlignRight\t: "靠右對齊",\r\n
DlgImgAlignTextTop\t: "文字上方",\r\n
DlgImgAlignTop\t\t: "靠上對齊",\r\n
DlgImgPreview\t\t: "預覽",\r\n
DlgImgAlertUrl\t\t: "請輸入影像 URL",\r\n
DlgImgLinkTab\t\t: "超連結",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Flash 屬性",\r\n
DlgFlashChkPlay\t\t: "自動播放",\r\n
DlgFlashChkLoop\t\t: "重複",\r\n
DlgFlashChkMenu\t\t: "開啟選單",\r\n
DlgFlashScale\t\t: "縮放",\r\n
DlgFlashScaleAll\t: "全部顯示",\r\n
DlgFlashScaleNoBorder\t: "無邊框",\r\n
DlgFlashScaleFit\t: "精確符合",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "超連結",\r\n
DlgLnkInfoTab\t\t: "超連結資訊",\r\n
DlgLnkTargetTab\t\t: "目標",\r\n
\r\n
DlgLnkType\t\t\t: "超連接類型",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "本頁錨點",\r\n
DlgLnkTypeEMail\t\t: "電子郵件",\r\n
DlgLnkProto\t\t\t: "通訊協定",\r\n
DlgLnkProtoOther\t: "<其他>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "請選擇錨點",\r\n
DlgLnkAnchorByName\t: "依錨點名稱",\r\n
DlgLnkAnchorById\t: "依元件 ID",\r\n
DlgLnkNoAnchors\t\t: "(本文件尚無可用之錨點)",\r\n
DlgLnkEMail\t\t\t: "電子郵件",\r\n
DlgLnkEMailSubject\t: "郵件主旨",\r\n
DlgLnkEMailBody\t\t: "郵件內容",\r\n
DlgLnkUpload\t\t: "上傳",\r\n
DlgLnkBtnUpload\t\t: "傳送至伺服器",\r\n
\r\n
DlgLnkTarget\t\t: "目標",\r\n
DlgLnkTargetFrame\t: "<框架>",\r\n
DlgLnkTargetPopup\t: "<快顯視窗>",\r\n
DlgLnkTargetBlank\t: "新視窗 (_blank)",\r\n
DlgLnkTargetParent\t: "父視窗 (_parent)",\r\n
DlgLnkTargetSelf\t: "本視窗 (_self)",\r\n
DlgLnkTargetTop\t\t: "最上層視窗 (_top)",\r\n
DlgLnkTargetFrameName\t: "目標框架名稱",\r\n
DlgLnkPopWinName\t: "快顯視窗名稱",\r\n
DlgLnkPopWinFeat\t: "快顯視窗屬性",\r\n
DlgLnkPopResize\t\t: "可調整大小",\r\n
DlgLnkPopLocation\t: "網址列",\r\n
DlgLnkPopMenu\t\t: "選單列",\r\n
DlgLnkPopScroll\t\t: "捲軸",\r\n
DlgLnkPopStatus\t\t: "狀態列",\r\n
DlgLnkPopToolbar\t: "工具列",\r\n
DlgLnkPopFullScrn\t: "全螢幕 (IE)",\r\n
DlgLnkPopDependent\t: "從屬 (NS)",\r\n
DlgLnkPopWidth\t\t: "寬",\r\n
DlgLnkPopHeight\t\t: "高",\r\n
DlgLnkPopLeft\t\t: "左",\r\n
DlgLnkPopTop\t\t: "右",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "請輸入欲連結的 URL",\r\n
DlnLnkMsgNoEMail\t: "請輸入電子郵件位址",\r\n
DlnLnkMsgNoAnchor\t: "請選擇錨點",\r\n
DlnLnkMsgInvPopName\t: "快顯名稱必須以「英文字母」為開頭，且不得含有空白",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "請選擇顏色",\r\n
DlgColorBtnClear\t: "清除",\r\n
DlgColorHighlight\t: "預覽",\r\n
DlgColorSelected\t: "選擇",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "插入表情符號",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "請選擇特殊符號",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "表格屬性",\r\n
DlgTableRows\t\t: "列數",\r\n
DlgTableColumns\t\t: "欄數",\r\n
DlgTableBorder\t\t: "邊框",\r\n
DlgTableAlign\t\t: "對齊",\r\n
DlgTableAlignNotSet\t: "<未設定>",\r\n
DlgTableAlignLeft\t: "靠左對齊",\r\n
DlgTableAlignCenter\t: "置中",\r\n
DlgTableAlignRight\t: "靠右對齊",\r\n
DlgTableWidth\t\t: "寬度",\r\n
DlgTableWidthPx\t\t: "像素",\r\n
DlgTableWidthPc\t\t: "百分比",\r\n
DlgTableHeight\t\t: "高度",\r\n
DlgTableCellSpace\t: "間距",\r\n
DlgTableCellPad\t\t: "內距",\r\n
DlgTableCaption\t\t: "標題",\r\n
DlgTableSummary\t\t: "摘要",\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "儲存格屬性",\r\n
DlgCellWidth\t\t: "寬度",\r\n
DlgCellWidthPx\t\t: "像素",\r\n
DlgCellWidthPc\t\t: "百分比",\r\n
DlgCellHeight\t\t: "高度",\r\n
DlgCellWordWrap\t\t: "自動換行",\r\n
DlgCellWordWrapNotSet\t: "<尚未設定>",\r\n
DlgCellWordWrapYes\t: "是",\r\n
DlgCellWordWrapNo\t: "否",\r\n
DlgCellHorAlign\t\t: "水平對齊",\r\n
DlgCellHorAlignNotSet\t: "<尚未設定>",\r\n
DlgCellHorAlignLeft\t: "靠左對齊",\r\n
DlgCellHorAlignCenter\t: "置中",\r\n
DlgCellHorAlignRight: "靠右對齊",\r\n
DlgCellVerAlign\t\t: "垂直對齊",\r\n
DlgCellVerAlignNotSet\t: "<尚未設定>",\r\n
DlgCellVerAlignTop\t: "靠上對齊",\r\n
DlgCellVerAlignMiddle\t: "置中",\r\n
DlgCellVerAlignBottom\t: "靠下對齊",\r\n
DlgCellVerAlignBaseline\t: "基準線",\r\n
DlgCellType\t\t: "儲存格類型",\r\n
DlgCellTypeData\t\t: "資料",\r\n
DlgCellTypeHeader\t: "標題",\r\n
DlgCellRowSpan\t\t: "合併列數",\r\n
DlgCellCollSpan\t\t: "合併欄数",\r\n
DlgCellBackColor\t: "背景顏色",\r\n
DlgCellBorderColor\t: "邊框顏色",\r\n
DlgCellBtnSelect\t: "請選擇…",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "尋找與取代",\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "尋找",\r\n
DlgFindFindBtn\t\t: "尋找",\r\n
DlgFindNotFoundMsg\t: "未找到指定的文字。",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "取代",\r\n
DlgReplaceFindLbl\t\t: "尋找:",\r\n
DlgReplaceReplaceLbl\t: "取代:",\r\n
DlgReplaceCaseChk\t\t: "大小寫須相符",\r\n
DlgReplaceReplaceBtn\t: "取代",\r\n
DlgReplaceReplAllBtn\t: "全部取代",\r\n
DlgReplaceWordChk\t\t: "全字相符",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "瀏覽器的安全性設定不允許編輯器自動執行剪下動作。請使用快捷鍵 (Ctrl+X) 剪下。",\r\n
PasteErrorCopy\t: "瀏覽器的安全性設定不允許編輯器自動執行複製動作。請使用快捷鍵 (Ctrl+C) 複製。",\r\n
\r\n
PasteAsText\t\t: "貼為純文字格式",\r\n
PasteFromWord\t: "自 Word 貼上",\r\n
\r\n
DlgPasteMsg2\t: "請使用快捷鍵 (<strong>Ctrl+V</strong>) 貼到下方區域中並按下 <strong>確定</strong>",\r\n
DlgPasteSec\t\t: "因為瀏覽器的安全性設定，本編輯器無法直接存取您的剪貼簿資料，請您自行在本視窗進行貼上動作。",\r\n
DlgPasteIgnoreFont\t\t: "移除字型設定",\r\n
DlgPasteRemoveStyles\t: "移除樣式設定",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "自動",\r\n
ColorMoreColors\t: "更多顏色…",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "文件屬性",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "命名錨點",\r\n
DlgAnchorName\t\t: "錨點名稱",\r\n
DlgAnchorErrorName\t: "請輸入錨點名稱",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "不在字典中",\r\n
DlgSpellChangeTo\t\t: "更改為",\r\n
DlgSpellBtnIgnore\t\t: "忽略",\r\n
DlgSpellBtnIgnoreAll\t: "全部忽略",\r\n
DlgSpellBtnReplace\t\t: "取代",\r\n
DlgSpellBtnReplaceAll\t: "全部取代",\r\n
DlgSpellBtnUndo\t\t\t: "復原",\r\n
DlgSpellNoSuggestions\t: "- 無建議值 -",\r\n
DlgSpellProgress\t\t: "進行拼字檢查中…",\r\n
DlgSpellNoMispell\t\t: "拼字檢查完成：未發現拼字錯誤",\r\n
DlgSpellNoChanges\t\t: "拼字檢查完成：未更改任何單字",\r\n
DlgSpellOneChange\t\t: "拼字檢查完成：更改了 1 個單字",\r\n
DlgSpellManyChanges\t\t: "拼字檢查完成：更改了 %1 個單字",\r\n
\r\n
IeSpellDownload\t\t\t: "尚未安裝拼字檢查元件。您是否想要現在下載？",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "顯示文字 (值)",\r\n
DlgButtonType\t\t: "類型",\r\n
DlgButtonTypeBtn\t: "按鈕 (Button)",\r\n
DlgButtonTypeSbm\t: "送出 (Submit)",\r\n
DlgButtonTypeRst\t: "重設 (Reset)",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "名稱",\r\n
DlgCheckboxValue\t: "選取值",\r\n
DlgCheckboxSelected\t: "已選取",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "名稱",\r\n
DlgFormAction\t: "動作",\r\n
DlgFormMethod\t: "方法",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "名稱",\r\n
DlgSelectValue\t\t: "選取值",\r\n
DlgSelectSize\t\t: "大小",\r\n
DlgSelectLines\t\t: "行",\r\n
DlgSelectChkMulti\t: "可多選",\r\n
DlgSelectOpAvail\t: "可用選項",\r\n
DlgSelectOpText\t\t: "顯示文字",\r\n
DlgSelectOpValue\t: "值",\r\n
DlgSelectBtnAdd\t\t: "新增",\r\n
DlgSelectBtnModify\t: "修改",\r\n
DlgSelectBtnUp\t\t: "上移",\r\n
DlgSelectBtnDown\t: "下移",\r\n
DlgSelectBtnSetValue : "設為預設值",\r\n
DlgSelectBtnDelete\t: "刪除",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "名稱",\r\n
DlgTextareaCols\t: "字元寬度",\r\n
DlgTextareaRows\t: "列數",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "名稱",\r\n
DlgTextValue\t\t: "值",\r\n
DlgTextCharWidth\t: "字元寬度",\r\n
DlgTextMaxChars\t\t: "最多字元數",\r\n
DlgTextType\t\t\t: "類型",\r\n
DlgTextTypeText\t\t: "文字",\r\n
DlgTextTypePass\t\t: "密碼",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "名稱",\r\n
DlgHiddenValue\t: "值",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "項目清單屬性",\r\n
NumberedListProp\t: "編號清單屬性",\r\n
DlgLstStart\t\t\t: "起始編號",\r\n
DlgLstType\t\t\t: "清單類型",\r\n
DlgLstTypeCircle\t: "圓圈",\r\n
DlgLstTypeDisc\t\t: "圓點",\r\n
DlgLstTypeSquare\t: "方塊",\r\n
DlgLstTypeNumbers\t: "數字 (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "小寫字母 (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "大寫字母 (A, B, C)",\r\n
DlgLstTypeSRoman\t: "小寫羅馬數字 (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "大寫羅馬數字 (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "一般",\r\n
DlgDocBackTab\t\t: "背景",\r\n
DlgDocColorsTab\t\t: "顯色與邊界",\r\n
DlgDocMetaTab\t\t: "Meta 資料",\r\n
\r\n
DlgDocPageTitle\t\t: "頁面標題",\r\n
DlgDocLangDir\t\t: "語言方向",\r\n
DlgDocLangDirLTR\t: "由左而右 (LTR)",\r\n
DlgDocLangDirRTL\t: "由右而左 (RTL)",\r\n
DlgDocLangCode\t\t: "語言代碼",\r\n
DlgDocCharSet\t\t: "字元編碼",\r\n
DlgDocCharSetCE\t\t: "中歐語系",\r\n
DlgDocCharSetCT\t\t: "正體中文 (Big5)",\r\n
DlgDocCharSetCR\t\t: "斯拉夫文",\r\n
DlgDocCharSetGR\t\t: "希臘文",\r\n
DlgDocCharSetJP\t\t: "日文",\r\n
DlgDocCharSetKR\t\t: "韓文",\r\n
DlgDocCharSetTR\t\t: "土耳其文",\r\n
DlgDocCharSetUN\t\t: "Unicode (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "西歐語系",\r\n
DlgDocCharSetOther\t: "其他字元編碼",\r\n
\r\n
DlgDocDocType\t\t: "文件類型",\r\n
DlgDocDocTypeOther\t: "其他文件類型",\r\n
DlgDocIncXHTML\t\t: "包含 XHTML 定義",\r\n
DlgDocBgColor\t\t: "背景顏色",\r\n
DlgDocBgImage\t\t: "背景影像",\r\n
DlgDocBgNoScroll\t: "浮水印",\r\n
DlgDocCText\t\t\t: "文字",\r\n
DlgDocCLink\t\t\t: "超連結",\r\n
DlgDocCVisited\t\t: "已瀏覽過的超連結",\r\n
DlgDocCActive\t\t: "作用中的超連結",\r\n
DlgDocMargins\t\t: "頁面邊界",\r\n
DlgDocMaTop\t\t\t: "上",\r\n
DlgDocMaLeft\t\t: "左",\r\n
DlgDocMaRight\t\t: "右",\r\n
DlgDocMaBottom\t\t: "下",\r\n
DlgDocMeIndex\t\t: "文件索引關鍵字 (用半形逗號[,]分隔)",\r\n
DlgDocMeDescr\t\t: "文件說明",\r\n
DlgDocMeAuthor\t\t: "作者",\r\n
DlgDocMeCopy\t\t: "版權所有",\r\n
DlgDocPreview\t\t: "預覽",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "樣版",\r\n
DlgTemplatesTitle\t: "內容樣版",\r\n
DlgTemplatesSelMsg\t: "請選擇欲開啟的樣版<br> (原有的內容將會被清除):",\r\n
DlgTemplatesLoading\t: "讀取樣版清單中，請稍候…",\r\n
DlgTemplatesNoTpl\t: "(無樣版)",\r\n
DlgTemplatesReplace\t: "取代原有內容",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "關於",\r\n
DlgAboutBrowserInfoTab\t: "瀏覽器資訊",\r\n
DlgAboutLicenseTab\t: "許可證",\r\n
DlgAboutVersion\t\t: "版本",\r\n
DlgAboutInfo\t\t: "想獲得更多資訊請至 ",\r\n
\r\n
// Div Dialog\r\n
DlgDivGeneralTab\t: "一般",\r\n
DlgDivAdvancedTab\t: "進階",\r\n
DlgDivStyle\t\t: "樣式",\r\n
DlgDivInlineStyle\t: "CSS 樣式",\r\n
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
            <value> <int>17920</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
