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
            <value> <string>vi.js</string> </value>
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
 * Vietnamese language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Thu gọn Thanh công cụ",\r\n
ToolbarExpand\t\t: "Mở rộng Thanh công cụ",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Lưu",\r\n
NewPage\t\t\t\t: "Trang mới",\r\n
Preview\t\t\t\t: "Xem trước",\r\n
Cut\t\t\t\t\t: "Cắt",\r\n
Copy\t\t\t\t: "Sao chép",\r\n
Paste\t\t\t\t: "Dán",\r\n
PasteText\t\t\t: "Dán theo dạng văn bản thuần",\r\n
PasteWord\t\t\t: "Dán với định dạng Word",\r\n
Print\t\t\t\t: "In",\r\n
SelectAll\t\t\t: "Chọn Tất cả",\r\n
RemoveFormat\t\t: "Xoá Định dạng",\r\n
InsertLinkLbl\t\t: "Liên kết",\r\n
InsertLink\t\t\t: "Chèn/Sửa Liên kết",\r\n
RemoveLink\t\t\t: "Xoá Liên kết",\r\n
VisitLink\t\t\t: "Mở Liên Kết",\r\n
Anchor\t\t\t\t: "Chèn/Sửa Neo",\r\n
AnchorDelete\t\t: "Gỡ bỏ Neo",\r\n
InsertImageLbl\t\t: "Hình ảnh",\r\n
InsertImage\t\t\t: "Chèn/Sửa Hình ảnh",\r\n
InsertFlashLbl\t\t: "Flash",\r\n
InsertFlash\t\t\t: "Chèn/Sửa Flash",\r\n
InsertTableLbl\t\t: "Bảng",\r\n
InsertTable\t\t\t: "Chèn/Sửa Bảng",\r\n
InsertLineLbl\t\t: "Đường phân cách ngang",\r\n
InsertLine\t\t\t: "Chèn Đường phân cách ngang",\r\n
InsertSpecialCharLbl: "Ký tự đặc biệt",\r\n
InsertSpecialChar\t: "Chèn Ký tự đặc biệt",\r\n
InsertSmileyLbl\t\t: "Hình biểu lộ cảm xúc (mặt cười)",\r\n
InsertSmiley\t\t: "Chèn Hình biểu lộ cảm xúc (mặt cười)",\r\n
About\t\t\t\t: "Giới thiệu về FCKeditor",\r\n
Bold\t\t\t\t: "Đậm",\r\n
Italic\t\t\t\t: "Nghiêng",\r\n
Underline\t\t\t: "Gạch chân",\r\n
StrikeThrough\t\t: "Gạch xuyên ngang",\r\n
Subscript\t\t\t: "Chỉ số dưới",\r\n
Superscript\t\t\t: "Chỉ số trên",\r\n
LeftJustify\t\t\t: "Canh trái",\r\n
CenterJustify\t\t: "Canh giữa",\r\n
RightJustify\t\t: "Canh phải",\r\n
BlockJustify\t\t: "Canh đều",\r\n
DecreaseIndent\t\t: "Dịch ra ngoài",\r\n
IncreaseIndent\t\t: "Dịch vào trong",\r\n
Blockquote\t\t\t: "Khối Trích dẫn",\r\n
CreateDiv\t\t\t: "Tạo Div Container",\r\n
EditDiv\t\t\t\t: "Chỉnh sửa Div Container",\r\n
DeleteDiv\t\t\t: "Gỡ bỏ Div Container",\r\n
Undo\t\t\t\t: "Khôi phục thao tác",\r\n
Redo\t\t\t\t: "Làm lại thao tác",\r\n
NumberedListLbl\t\t: "Danh sách có thứ tự",\r\n
NumberedList\t\t: "Chèn/Xoá Danh sách có thứ tự",\r\n
BulletedListLbl\t\t: "Danh sách không thứ tự",\r\n
BulletedList\t\t: "Chèn/Xoá Danh sách không thứ tự",\r\n
ShowTableBorders\t: "Hiển thị Đường viền bảng",\r\n
ShowDetails\t\t\t: "Hiển thị Chi tiết",\r\n
Style\t\t\t\t: "Mẫu",\r\n
FontFormat\t\t\t: "Định dạng",\r\n
Font\t\t\t\t: "Phông",\r\n
FontSize\t\t\t: "Cỡ chữ",\r\n
TextColor\t\t\t: "Màu chữ",\r\n
BGColor\t\t\t\t: "Màu nền",\r\n
Source\t\t\t\t: "Mã HTML",\r\n
Find\t\t\t\t: "Tìm kiếm",\r\n
Replace\t\t\t\t: "Thay thế",\r\n
SpellCheck\t\t\t: "Kiểm tra Chính tả",\r\n
UniversalKeyboard\t: "Bàn phím Quốc tế",\r\n
PageBreakLbl\t\t: "Ngắt trang",\r\n
PageBreak\t\t\t: "Chèn Ngắt trang",\r\n
\r\n
Form\t\t\t: "Biểu mẫu",\r\n
Checkbox\t\t: "Nút kiểm",\r\n
RadioButton\t\t: "Nút chọn",\r\n
TextField\t\t: "Trường văn bản",\r\n
Textarea\t\t: "Vùng văn bản",\r\n
HiddenField\t\t: "Trường ẩn",\r\n
Button\t\t\t: "Nút",\r\n
SelectionField\t: "Ô chọn",\r\n
ImageButton\t\t: "Nút hình ảnh",\r\n
\r\n
FitWindow\t\t: "Mở rộng tối đa kích thước trình biên tập",\r\n
ShowBlocks\t\t: "Hiển thị các Khối",\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Sửa Liên kết",\r\n
CellCM\t\t\t\t: "Ô",\r\n
RowCM\t\t\t\t: "Hàng",\r\n
ColumnCM\t\t\t: "Cột",\r\n
InsertRowAfter\t\t: "Chèn Hàng Phía sau",\r\n
InsertRowBefore\t\t: "Chèn Hàng Phía trước",\r\n
DeleteRows\t\t\t: "Xoá Hàng",\r\n
InsertColumnAfter\t: "Chèn Cột Phía sau",\r\n
InsertColumnBefore\t: "Chèn Cột Phía trước",\r\n
DeleteColumns\t\t: "Xoá Cột",\r\n
InsertCellAfter\t\t: "Chèn Ô Phía sau",\r\n
InsertCellBefore\t: "Chèn Ô Phía trước",\r\n
DeleteCells\t\t\t: "Xoá Ô",\r\n
MergeCells\t\t\t: "Kết hợp Ô",\r\n
MergeRight\t\t\t: "Kết hợp Sang phải",\r\n
MergeDown\t\t\t: "Kết hợp Xuống dưới",\r\n
HorizontalSplitCell\t: "Tách ngang Ô",\r\n
VerticalSplitCell\t: "Tách dọc Ô",\r\n
TableDelete\t\t\t: "Xóa Bảng",\r\n
CellProperties\t\t: "Thuộc tính Ô",\r\n
TableProperties\t\t: "Thuộc tính Bảng",\r\n
ImageProperties\t\t: "Thuộc tính Hình ảnh",\r\n
FlashProperties\t\t: "Thuộc tính Flash",\r\n
\r\n
AnchorProp\t\t\t: "Thuộc tính Neo",\r\n
ButtonProp\t\t\t: "Thuộc tính Nút",\r\n
CheckboxProp\t\t: "Thuộc tính Nút kiểm",\r\n
HiddenFieldProp\t\t: "Thuộc tính Trường ẩn",\r\n
RadioButtonProp\t\t: "Thuộc tính Nút chọn",\r\n
ImageButtonProp\t\t: "Thuộc tính Nút hình ảnh",\r\n
TextFieldProp\t\t: "Thuộc tính Trường văn bản",\r\n
SelectionFieldProp\t: "Thuộc tính Ô chọn",\r\n
TextareaProp\t\t: "Thuộc tính Vùng văn bản",\r\n
FormProp\t\t\t: "Thuộc tính Biểu mẫu",\r\n
\r\n
FontFormats\t\t\t: "Normal;Formatted;Address;Heading 1;Heading 2;Heading 3;Heading 4;Heading 5;Heading 6;Normal (DIV)",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "Đang xử lý XHTML. Vui lòng đợi trong giây lát...",\r\n
Done\t\t\t\t: "Đã hoàn thành",\r\n
PasteWordConfirm\t: "Văn bản bạn muốn dán có kèm định dạng của Word. Bạn có muốn loại bỏ định dạng Word trước khi dán?",\r\n
NotCompatiblePaste\t: "Lệnh này chỉ được hỗ trợ từ trình duyệt Internet Explorer phiên bản 5.5 hoặc mới hơn. Bạn có muốn dán nguyên mẫu?",\r\n
UnknownToolbarItem\t: "Không rõ mục trên thanh công cụ \\"%1\\"",\r\n
UnknownCommand\t\t: "Không rõ lệnh \\"%1\\"",\r\n
NotImplemented\t\t: "Lệnh không được thực hiện",\r\n
UnknownToolbarSet\t: "Thanh công cụ \\"%1\\" không tồn tại",\r\n
NoActiveX\t\t\t: "Các thiết lập bảo mật của trình duyệt có thể giới hạn một số chức năng của trình biên tập. Bạn phải bật tùy chọn \\"Run ActiveX controls and plug-ins\\". Bạn có thể gặp một số lỗi và thấy thiếu một số chức năng.",\r\n
BrowseServerBlocked : "Không thể mở được bộ duyệt tài nguyên. Hãy đảm bảo chức năng chặn popup đã bị vô hiệu hóa.",\r\n
DialogBlocked\t\t: "Không thể mở được cửa sổ hộp thoại. Hãy đảm bảo chức năng chặn popup đã bị vô hiệu hóa.",\r\n
VisitLinkBlocked\t: "Không thể mở được cửa sổ trình duyệt mới. Hãy đảm bảo chức năng chặn popup đã bị vô hiệu hóa.",\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "Đồng ý",\r\n
DlgBtnCancel\t\t: "Bỏ qua",\r\n
DlgBtnClose\t\t\t: "Đóng",\r\n
DlgBtnBrowseServer\t: "Duyệt trên máy chủ",\r\n
DlgAdvancedTag\t\t: "Mở rộng",\r\n
DlgOpOther\t\t\t: "<Khác>",\r\n
DlgInfoTab\t\t\t: "Thông tin",\r\n
DlgAlertUrl\t\t\t: "Hãy nhập vào một URL",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<không thiết lập>",\r\n
DlgGenId\t\t\t: "Định danh",\r\n
DlgGenLangDir\t\t: "Đường dẫn Ngôn ngữ",\r\n
DlgGenLangDirLtr\t: "Trái sang Phải (LTR)",\r\n
DlgGenLangDirRtl\t: "Phải sang Trái (RTL)",\r\n
DlgGenLangCode\t\t: "Mã Ngôn ngữ",\r\n
DlgGenAccessKey\t\t: "Phím Hỗ trợ truy cập",\r\n
DlgGenName\t\t\t: "Tên",\r\n
DlgGenTabIndex\t\t: "Chỉ số của Tab",\r\n
DlgGenLongDescr\t\t: "Mô tả URL",\r\n
DlgGenClass\t\t\t: "Lớp Stylesheet",\r\n
DlgGenTitle\t\t\t: "Advisory Title",\r\n
DlgGenContType\t\t: "Advisory Content Type",\r\n
DlgGenLinkCharset\t: "Bảng mã của tài nguyên được liên kết đến",\r\n
DlgGenStyle\t\t\t: "Mẫu",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Thuộc tính Hình ảnh",\r\n
DlgImgInfoTab\t\t: "Thông tin Hình ảnh",\r\n
DlgImgBtnUpload\t\t: "Tải lên Máy chủ",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "Tải lên",\r\n
DlgImgAlt\t\t\t: "Chú thích Hình ảnh",\r\n
DlgImgWidth\t\t\t: "Rộng",\r\n
DlgImgHeight\t\t: "Cao",\r\n
DlgImgLockRatio\t\t: "Giữ nguyên tỷ lệ",\r\n
DlgBtnResetSize\t\t: "Kích thước gốc",\r\n
DlgImgBorder\t\t: "Đường viền",\r\n
DlgImgHSpace\t\t: "HSpace",\r\n
DlgImgVSpace\t\t: "VSpace",\r\n
DlgImgAlign\t\t\t: "Vị trí",\r\n
DlgImgAlignLeft\t\t: "Trái",\r\n
DlgImgAlignAbsBottom: "Dưới tuyệt đối",\r\n
DlgImgAlignAbsMiddle: "Giữa tuyệt đối",\r\n
DlgImgAlignBaseline\t: "Đường cơ sở",\r\n
DlgImgAlignBottom\t: "Dưới",\r\n
DlgImgAlignMiddle\t: "Giữa",\r\n
DlgImgAlignRight\t: "Phải",\r\n
DlgImgAlignTextTop\t: "Phía trên chữ",\r\n
DlgImgAlignTop\t\t: "Trên",\r\n
DlgImgPreview\t\t: "Xem trước",\r\n
DlgImgAlertUrl\t\t: "Hãy đưa vào URL của hình ảnh",\r\n
DlgImgLinkTab\t\t: "Liên kết",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Thuộc tính Flash",\r\n
DlgFlashChkPlay\t\t: "Tự động chạy",\r\n
DlgFlashChkLoop\t\t: "Lặp",\r\n
DlgFlashChkMenu\t\t: "Cho phép bật Menu của Flash",\r\n
DlgFlashScale\t\t: "Tỷ lệ",\r\n
DlgFlashScaleAll\t: "Hiển thị tất cả",\r\n
DlgFlashScaleNoBorder\t: "Không đường viền",\r\n
DlgFlashScaleFit\t: "Vừa vặn",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Liên kết",\r\n
DlgLnkInfoTab\t\t: "Thông tin Liên kết",\r\n
DlgLnkTargetTab\t\t: "Đích",\r\n
\r\n
DlgLnkType\t\t\t: "Kiểu Liên kết",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Neo trong trang này",\r\n
DlgLnkTypeEMail\t\t: "Thư điện tử",\r\n
DlgLnkProto\t\t\t: "Giao thức",\r\n
DlgLnkProtoOther\t: "<khác>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Chọn một Neo",\r\n
DlgLnkAnchorByName\t: "Theo Tên Neo",\r\n
DlgLnkAnchorById\t: "Theo Định danh Element",\r\n
DlgLnkNoAnchors\t\t: "(Không có Neo nào trong tài liệu)",\r\n
DlgLnkEMail\t\t\t: "Thư điện tử",\r\n
DlgLnkEMailSubject\t: "Tiêu đề Thông điệp",\r\n
DlgLnkEMailBody\t\t: "Nội dung Thông điệp",\r\n
DlgLnkUpload\t\t: "Tải lên",\r\n
DlgLnkBtnUpload\t\t: "Tải lên Máy chủ",\r\n
\r\n
DlgLnkTarget\t\t: "Đích",\r\n
DlgLnkTargetFrame\t: "<khung>",\r\n
DlgLnkTargetPopup\t: "<cửa sổ popup>",\r\n
DlgLnkTargetBlank\t: "Cửa sổ mới (_blank)",\r\n
DlgLnkTargetParent\t: "Cửa sổ cha (_parent)",\r\n
DlgLnkTargetSelf\t: "Cùng cửa sổ (_self)",\r\n
DlgLnkTargetTop\t\t: "Cửa sổ trên cùng(_top)",\r\n
DlgLnkTargetFrameName\t: "Tên Khung đích",\r\n
DlgLnkPopWinName\t: "Tên Cửa sổ Popup",\r\n
DlgLnkPopWinFeat\t: "Đặc điểm của Cửa sổ Popup",\r\n
DlgLnkPopResize\t\t: "Kích thước thay đổi",\r\n
DlgLnkPopLocation\t: "Thanh vị trí",\r\n
DlgLnkPopMenu\t\t: "Thanh Menu",\r\n
DlgLnkPopScroll\t\t: "Thanh cuộn",\r\n
DlgLnkPopStatus\t\t: "Thanh trạng thái",\r\n
DlgLnkPopToolbar\t: "Thanh công cụ",\r\n
DlgLnkPopFullScrn\t: "Toàn màn hình (IE)",\r\n
DlgLnkPopDependent\t: "Phụ thuộc (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Rộng",\r\n
DlgLnkPopHeight\t\t: "Cao",\r\n
DlgLnkPopLeft\t\t: "Vị trí Trái",\r\n
DlgLnkPopTop\t\t: "Vị trí Trên",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Hãy đưa vào Liên kết URL",\r\n
DlnLnkMsgNoEMail\t: "Hãy đưa vào địa chỉ thư điện tử",\r\n
DlnLnkMsgNoAnchor\t: "Hãy chọn một Neo",\r\n
DlnLnkMsgInvPopName\t: "Tên của cửa sổ Popup phải bắt đầu bằng một ký tự và không được chứa khoảng trắng",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Chọn màu",\r\n
DlgColorBtnClear\t: "Xoá",\r\n
DlgColorHighlight\t: "Tô sáng",\r\n
DlgColorSelected\t: "Đã chọn",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Chèn Hình biểu lộ cảm xúc (mặt cười)",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Hãy chọn Ký tự đặc biệt",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Thuộc tính bảng",\r\n
DlgTableRows\t\t: "Hàng",\r\n
DlgTableColumns\t\t: "Cột",\r\n
DlgTableBorder\t\t: "Cỡ Đường viền",\r\n
DlgTableAlign\t\t: "Canh lề",\r\n
DlgTableAlignNotSet\t: "<Chưa thiết lập>",\r\n
DlgTableAlignLeft\t: "Trái",\r\n
DlgTableAlignCenter\t: "Giữa",\r\n
DlgTableAlignRight\t: "Phải",\r\n
DlgTableWidth\t\t: "Rộng",\r\n
DlgTableWidthPx\t\t: "điểm (px)",\r\n
DlgTableWidthPc\t\t: "%",\r\n
DlgTableHeight\t\t: "Cao",\r\n
DlgTableCellSpace\t: "Khoảng cách Ô",\r\n
DlgTableCellPad\t\t: "Đệm Ô",\r\n
DlgTableCaption\t\t: "Đầu đề",\r\n
DlgTableSummary\t\t: "Tóm lược",\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Thuộc tính Ô",\r\n
DlgCellWidth\t\t: "Rộng",\r\n
DlgCellWidthPx\t\t: "điểm (px)",\r\n
DlgCellWidthPc\t\t: "%",\r\n
DlgCellHeight\t\t: "Cao",\r\n
DlgCellWordWrap\t\t: "Bọc từ",\r\n
DlgCellWordWrapNotSet\t: "<Chưa thiết lập>",\r\n
DlgCellWordWrapYes\t: "Đồng ý",\r\n
DlgCellWordWrapNo\t: "Không",\r\n
DlgCellHorAlign\t\t: "Canh theo Chiều ngang",\r\n
DlgCellHorAlignNotSet\t: "<Chưa thiết lập>",\r\n
DlgCellHorAlignLeft\t: "Trái",\r\n
DlgCellHorAlignCenter\t: "Giữa",\r\n
DlgCellHorAlignRight: "Phải",\r\n
DlgCellVerAlign\t\t: "Canh theo Chiều dọc",\r\n
DlgCellVerAlignNotSet\t: "<Chưa thiết lập>",\r\n
DlgCellVerAlignTop\t: "Trên",\r\n
DlgCellVerAlignMiddle\t: "Giữa",\r\n
DlgCellVerAlignBottom\t: "Dưới",\r\n
DlgCellVerAlignBaseline\t: "Đường cơ sở",\r\n
DlgCellType\t\t: "Cell Type",\t//MISSING\r\n
DlgCellTypeData\t\t: "Data",\t//MISSING\r\n
DlgCellTypeHeader\t: "Header",\t//MISSING\r\n
DlgCellRowSpan\t\t: "Nối Hàng",\r\n
DlgCellCollSpan\t\t: "Nối Cột",\r\n
DlgCellBackColor\t: "Màu nền",\r\n
DlgCellBorderColor\t: "Màu viền",\r\n
DlgCellBtnSelect\t: "Chọn...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Tìm kiếm và Thay Thế",\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Tìm kiếm",\r\n
DlgFindFindBtn\t\t: "Tìm kiếm",\r\n
DlgFindNotFoundMsg\t: "Không tìm thấy chuỗi cần tìm.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Thay thế",\r\n
DlgReplaceFindLbl\t\t: "Tìm chuỗi:",\r\n
DlgReplaceReplaceLbl\t: "Thay bằng:",\r\n
DlgReplaceCaseChk\t\t: "Phân biệt chữ hoa/thường",\r\n
DlgReplaceReplaceBtn\t: "Thay thế",\r\n
DlgReplaceReplAllBtn\t: "Thay thế Tất cả",\r\n
DlgReplaceWordChk\t\t: "Đúng toàn bộ từ",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "Các thiết lập bảo mật của trình duyệt không cho phép trình biên tập tự động thực thi lệnh cắt. Hãy sử dụng bàn phím cho lệnh này (Ctrl+X).",\r\n
PasteErrorCopy\t: "Các thiết lập bảo mật của trình duyệt không cho phép trình biên tập tự động thực thi lệnh sao chép. Hãy sử dụng bàn phím cho lệnh này (Ctrl+C).",\r\n
\r\n
PasteAsText\t\t: "Dán theo định dạng văn bản thuần",\r\n
PasteFromWord\t: "Dán với định dạng Word",\r\n
\r\n
DlgPasteMsg2\t: "Hãy dán nội dung vào trong khung bên dưới, sử dụng tổ hợp phím (<STRONG>Ctrl+V</STRONG>) và nhấn vào nút <STRONG>Đồng ý</STRONG>.",\r\n
DlgPasteSec\t\t: "Because of your browser security settings, the editor is not able to access your clipboard data directly. You are required to paste it again in this window.",\t//MISSING\r\n
DlgPasteIgnoreFont\t\t: "Chấp nhận các định dạng phông",\r\n
DlgPasteRemoveStyles\t: "Gỡ bỏ các định dạng Styles",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Tự động",\r\n
ColorMoreColors\t: "Màu khác...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Thuộc tính Tài liệu",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Thuộc tính Neo",\r\n
DlgAnchorName\t\t: "Tên của Neo",\r\n
DlgAnchorErrorName\t: "Hãy nhập vào tên của Neo",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Không có trong từ điển",\r\n
DlgSpellChangeTo\t\t: "Chuyển thành",\r\n
DlgSpellBtnIgnore\t\t: "Bỏ qua",\r\n
DlgSpellBtnIgnoreAll\t: "Bỏ qua Tất cả",\r\n
DlgSpellBtnReplace\t\t: "Thay thế",\r\n
DlgSpellBtnReplaceAll\t: "Thay thế Tất cả",\r\n
DlgSpellBtnUndo\t\t\t: "Phục hồi lại",\r\n
DlgSpellNoSuggestions\t: "- Không đưa ra gợi ý về từ -",\r\n
DlgSpellProgress\t\t: "Đang tiến hành kiểm tra chính tả...",\r\n
DlgSpellNoMispell\t\t: "Hoàn tất kiểm tra chính tả: Không có lỗi chính tả",\r\n
DlgSpellNoChanges\t\t: "Hoàn tất kiểm tra chính tả: Không có từ nào được thay đổi",\r\n
DlgSpellOneChange\t\t: "Hoàn tất kiểm tra chính tả: Một từ đã được thay đổi",\r\n
DlgSpellManyChanges\t\t: "Hoàn tất kiểm tra chính tả: %1 từ đã được thay đổi",\r\n
\r\n
IeSpellDownload\t\t\t: "Chức năng kiểm tra chính tả chưa được cài đặt. Bạn có muốn tải về ngay bây giờ?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Chuỗi hiển thị (Giá trị)",\r\n
DlgButtonType\t\t: "Kiểu",\r\n
DlgButtonTypeBtn\t: "Nút Bấm",\r\n
DlgButtonTypeSbm\t: "Nút Gửi",\r\n
DlgButtonTypeRst\t: "Nút Nhập lại",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Tên",\r\n
DlgCheckboxValue\t: "Giá trị",\r\n
DlgCheckboxSelected\t: "Được chọn",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Tên",\r\n
DlgFormAction\t: "Hành động",\r\n
DlgFormMethod\t: "Phương thức",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Tên",\r\n
DlgSelectValue\t\t: "Giá trị",\r\n
DlgSelectSize\t\t: "Kích cỡ",\r\n
DlgSelectLines\t\t: "dòng",\r\n
DlgSelectChkMulti\t: "Cho phép chọn nhiều",\r\n
DlgSelectOpAvail\t: "Các tùy chọn có thể sử dụng",\r\n
DlgSelectOpText\t\t: "Văn bản",\r\n
DlgSelectOpValue\t: "Giá trị",\r\n
DlgSelectBtnAdd\t\t: "Thêm",\r\n
DlgSelectBtnModify\t: "Thay đổi",\r\n
DlgSelectBtnUp\t\t: "Lên",\r\n
DlgSelectBtnDown\t: "Xuống",\r\n
DlgSelectBtnSetValue : "Giá trị được chọn",\r\n
DlgSelectBtnDelete\t: "Xoá",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Tên",\r\n
DlgTextareaCols\t: "Cột",\r\n
DlgTextareaRows\t: "Hàng",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Tên",\r\n
DlgTextValue\t\t: "Giá trị",\r\n
DlgTextCharWidth\t: "Rộng",\r\n
DlgTextMaxChars\t\t: "Số Ký tự tối đa",\r\n
DlgTextType\t\t\t: "Kiểu",\r\n
DlgTextTypeText\t\t: "Ký tự",\r\n
DlgTextTypePass\t\t: "Mật khẩu",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Tên",\r\n
DlgHiddenValue\t: "Giá trị",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Thuộc tính Danh sách không thứ tự",\r\n
NumberedListProp\t: "Thuộc tính Danh sách có thứ tự",\r\n
DlgLstStart\t\t\t: "Bắt đầu",\r\n
DlgLstType\t\t\t: "Kiểu",\r\n
DlgLstTypeCircle\t: "Hình tròn",\r\n
DlgLstTypeDisc\t\t: "Hình đĩa",\r\n
DlgLstTypeSquare\t: "Hình vuông",\r\n
DlgLstTypeNumbers\t: "Số thứ tự (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Chữ cái thường (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Chữ cái hoa (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Số La Mã thường (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Số La Mã hoa (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Toàn thể",\r\n
DlgDocBackTab\t\t: "Nền",\r\n
DlgDocColorsTab\t\t: "Màu sắc và Đường biên",\r\n
DlgDocMetaTab\t\t: "Siêu dữ liệu",\r\n
\r\n
DlgDocPageTitle\t\t: "Tiêu đề Trang",\r\n
DlgDocLangDir\t\t: "Đường dẫn Ngôn ngữ",\r\n
DlgDocLangDirLTR\t: "Trái sang Phải (LTR)",\r\n
DlgDocLangDirRTL\t: "Phải sang Trái (RTL)",\r\n
DlgDocLangCode\t\t: "Mã Ngôn ngữ",\r\n
DlgDocCharSet\t\t: "Bảng mã ký tự",\r\n
DlgDocCharSetCE\t\t: "Trung Âu",\r\n
DlgDocCharSetCT\t\t: "Tiếng Trung Quốc (Big5)",\r\n
DlgDocCharSetCR\t\t: "Tiếng Kirin",\r\n
DlgDocCharSetGR\t\t: "Tiếng Hy Lạp",\r\n
DlgDocCharSetJP\t\t: "Tiếng Nhật",\r\n
DlgDocCharSetKR\t\t: "Tiếng Hàn",\r\n
DlgDocCharSetTR\t\t: "Tiếng Thổ Nhĩ Kỳ",\r\n
DlgDocCharSetUN\t\t: "Unicode (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "Tây Âu",\r\n
DlgDocCharSetOther\t: "Bảng mã ký tự khác",\r\n
\r\n
DlgDocDocType\t\t: "Kiểu Đề mục Tài liệu",\r\n
DlgDocDocTypeOther\t: "Kiểu Đề mục Tài liệu khác",\r\n
DlgDocIncXHTML\t\t: "Bao gồm cả định nghĩa XHTML",\r\n
DlgDocBgColor\t\t: "Màu nền",\r\n
DlgDocBgImage\t\t: "URL của Hình ảnh nền",\r\n
DlgDocBgNoScroll\t: "Không cuộn nền",\r\n
DlgDocCText\t\t\t: "Văn bản",\r\n
DlgDocCLink\t\t\t: "Liên kết",\r\n
DlgDocCVisited\t\t: "Liên kết Đã ghé thăm",\r\n
DlgDocCActive\t\t: "Liên kết Hiện hành",\r\n
DlgDocMargins\t\t: "Đường biên của Trang",\r\n
DlgDocMaTop\t\t\t: "Trên",\r\n
DlgDocMaLeft\t\t: "Trái",\r\n
DlgDocMaRight\t\t: "Phải",\r\n
DlgDocMaBottom\t\t: "Dưới",\r\n
DlgDocMeIndex\t\t: "Các từ khóa chỉ mục tài liệu (phân cách bởi dấu phẩy)",\r\n
DlgDocMeDescr\t\t: "Mô tả tài liệu",\r\n
DlgDocMeAuthor\t\t: "Tác giả",\r\n
DlgDocMeCopy\t\t: "Bản quyền",\r\n
DlgDocPreview\t\t: "Xem trước",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Mẫu dựng sẵn",\r\n
DlgTemplatesTitle\t: "Nội dung Mẫu dựng sẵn",\r\n
DlgTemplatesSelMsg\t: "Hãy chọn Mẫu dựng sẵn để mở trong trình biên tập<br>(nội dung hiện tại sẽ bị mất):",\r\n
DlgTemplatesLoading\t: "Đang nạp Danh sách Mẫu dựng sẵn. Vui lòng đợi trong giây lát...",\r\n
DlgTemplatesNoTpl\t: "(Không có Mẫu dựng sẵn nào được định nghĩa)",\r\n
DlgTemplatesReplace\t: "Thay thế nội dung hiện tại",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Giới thiệu",\r\n
DlgAboutBrowserInfoTab\t: "Thông tin trình duyệt",\r\n
DlgAboutLicenseTab\t: "Giấy phép",\r\n
DlgAboutVersion\t\t: "phiên bản",\r\n
DlgAboutInfo\t\t: "Để biết thêm thông tin, hãy truy cập",\r\n
\r\n
// Div Dialog\r\n
DlgDivGeneralTab\t: "Chung",\r\n
DlgDivAdvancedTab\t: "Nâng cao",\r\n
DlgDivStyle\t\t: "Kiểu Style",\r\n
DlgDivInlineStyle\t: "Kiểu Style Trực tiếp",\r\n
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
            <value> <int>20991</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
