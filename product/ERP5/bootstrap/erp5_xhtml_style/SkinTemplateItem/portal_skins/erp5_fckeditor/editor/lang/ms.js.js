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
            <value> <string>ms.js</string> </value>
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
 * Malay language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Collapse Toolbar",\r\n
ToolbarExpand\t\t: "Expand Toolbar",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Simpan",\r\n
NewPage\t\t\t\t: "Helaian Baru",\r\n
Preview\t\t\t\t: "Prebiu",\r\n
Cut\t\t\t\t\t: "Potong",\r\n
Copy\t\t\t\t: "Salin",\r\n
Paste\t\t\t\t: "Tampal",\r\n
PasteText\t\t\t: "Tampal sebagai Text Biasa",\r\n
PasteWord\t\t\t: "Tampal dari Word",\r\n
Print\t\t\t\t: "Cetak",\r\n
SelectAll\t\t\t: "Pilih Semua",\r\n
RemoveFormat\t\t: "Buang Format",\r\n
InsertLinkLbl\t\t: "Sambungan",\r\n
InsertLink\t\t\t: "Masukkan/Sunting Sambungan",\r\n
RemoveLink\t\t\t: "Buang Sambungan",\r\n
VisitLink\t\t\t: "Open Link",\t//MISSING\r\n
Anchor\t\t\t\t: "Masukkan/Sunting Pautan",\r\n
AnchorDelete\t\t: "Remove Anchor",\t//MISSING\r\n
InsertImageLbl\t\t: "Gambar",\r\n
InsertImage\t\t\t: "Masukkan/Sunting Gambar",\r\n
InsertFlashLbl\t\t: "Flash",\t//MISSING\r\n
InsertFlash\t\t\t: "Insert/Edit Flash",\t//MISSING\r\n
InsertTableLbl\t\t: "Jadual",\r\n
InsertTable\t\t\t: "Masukkan/Sunting Jadual",\r\n
InsertLineLbl\t\t: "Garisan",\r\n
InsertLine\t\t\t: "Masukkan Garisan Membujur",\r\n
InsertSpecialCharLbl: "Huruf Istimewa",\r\n
InsertSpecialChar\t: "Masukkan Huruf Istimewa",\r\n
InsertSmileyLbl\t\t: "Smiley",\r\n
InsertSmiley\t\t: "Masukkan Smiley",\r\n
About\t\t\t\t: "Tentang FCKeditor",\r\n
Bold\t\t\t\t: "Bold",\r\n
Italic\t\t\t\t: "Italic",\r\n
Underline\t\t\t: "Underline",\r\n
StrikeThrough\t\t: "Strike Through",\r\n
Subscript\t\t\t: "Subscript",\r\n
Superscript\t\t\t: "Superscript",\r\n
LeftJustify\t\t\t: "Jajaran Kiri",\r\n
CenterJustify\t\t: "Jajaran Tengah",\r\n
RightJustify\t\t: "Jajaran Kanan",\r\n
BlockJustify\t\t: "Jajaran Blok",\r\n
DecreaseIndent\t\t: "Kurangkan Inden",\r\n
IncreaseIndent\t\t: "Tambahkan Inden",\r\n
Blockquote\t\t\t: "Blockquote",\t//MISSING\r\n
CreateDiv\t\t\t: "Create Div Container",\t//MISSING\r\n
EditDiv\t\t\t\t: "Edit Div Container",\t//MISSING\r\n
DeleteDiv\t\t\t: "Remove Div Container",\t//MISSING\r\n
Undo\t\t\t\t: "Batalkan",\r\n
Redo\t\t\t\t: "Ulangkan",\r\n
NumberedListLbl\t\t: "Senarai bernombor",\r\n
NumberedList\t\t: "Masukkan/Sunting Senarai bernombor",\r\n
BulletedListLbl\t\t: "Senarai tidak bernombor",\r\n
BulletedList\t\t: "Masukkan/Sunting Senarai tidak bernombor",\r\n
ShowTableBorders\t: "Tunjukkan Border Jadual",\r\n
ShowDetails\t\t\t: "Tunjukkan Butiran",\r\n
Style\t\t\t\t: "Stail",\r\n
FontFormat\t\t\t: "Format",\r\n
Font\t\t\t\t: "Font",\r\n
FontSize\t\t\t: "Saiz",\r\n
TextColor\t\t\t: "Warna Text",\r\n
BGColor\t\t\t\t: "Warna Latarbelakang",\r\n
Source\t\t\t\t: "Sumber",\r\n
Find\t\t\t\t: "Cari",\r\n
Replace\t\t\t\t: "Ganti",\r\n
SpellCheck\t\t\t: "Semak Ejaan",\r\n
UniversalKeyboard\t: "Papan Kekunci Universal",\r\n
PageBreakLbl\t\t: "Page Break",\t//MISSING\r\n
PageBreak\t\t\t: "Insert Page Break",\t//MISSING\r\n
\r\n
Form\t\t\t: "Borang",\r\n
Checkbox\t\t: "Checkbox",\r\n
RadioButton\t\t: "Butang Radio",\r\n
TextField\t\t: "Text Field",\r\n
Textarea\t\t: "Textarea",\r\n
HiddenField\t\t: "Field Tersembunyi",\r\n
Button\t\t\t: "Butang",\r\n
SelectionField\t: "Field Pilihan",\r\n
ImageButton\t\t: "Butang Bergambar",\r\n
\r\n
FitWindow\t\t: "Maximize the editor size",\t//MISSING\r\n
ShowBlocks\t\t: "Show Blocks",\t//MISSING\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Sunting Sambungan",\r\n
CellCM\t\t\t\t: "Cell",\t//MISSING\r\n
RowCM\t\t\t\t: "Row",\t//MISSING\r\n
ColumnCM\t\t\t: "Column",\t//MISSING\r\n
InsertRowAfter\t\t: "Insert Row After",\t//MISSING\r\n
InsertRowBefore\t\t: "Insert Row Before",\t//MISSING\r\n
DeleteRows\t\t\t: "Buangkan Baris",\r\n
InsertColumnAfter\t: "Insert Column After",\t//MISSING\r\n
InsertColumnBefore\t: "Insert Column Before",\t//MISSING\r\n
DeleteColumns\t\t: "Buangkan Lajur",\r\n
InsertCellAfter\t\t: "Insert Cell After",\t//MISSING\r\n
InsertCellBefore\t: "Insert Cell Before",\t//MISSING\r\n
DeleteCells\t\t\t: "Buangkan Sel-sel",\r\n
MergeCells\t\t\t: "Cantumkan Sel-sel",\r\n
MergeRight\t\t\t: "Merge Right",\t//MISSING\r\n
MergeDown\t\t\t: "Merge Down",\t//MISSING\r\n
HorizontalSplitCell\t: "Split Cell Horizontally",\t//MISSING\r\n
VerticalSplitCell\t: "Split Cell Vertically",\t//MISSING\r\n
TableDelete\t\t\t: "Delete Table",\t//MISSING\r\n
CellProperties\t\t: "Ciri-ciri Sel",\r\n
TableProperties\t\t: "Ciri-ciri Jadual",\r\n
ImageProperties\t\t: "Ciri-ciri Gambar",\r\n
FlashProperties\t\t: "Flash Properties",\t//MISSING\r\n
\r\n
AnchorProp\t\t\t: "Ciri-ciri Pautan",\r\n
ButtonProp\t\t\t: "Ciri-ciri Butang",\r\n
CheckboxProp\t\t: "Ciri-ciri Checkbox",\r\n
HiddenFieldProp\t\t: "Ciri-ciri Field Tersembunyi",\r\n
RadioButtonProp\t\t: "Ciri-ciri Butang Radio",\r\n
ImageButtonProp\t\t: "Ciri-ciri Butang Bergambar",\r\n
TextFieldProp\t\t: "Ciri-ciri Text Field",\r\n
SelectionFieldProp\t: "Ciri-ciri Selection Field",\r\n
TextareaProp\t\t: "Ciri-ciri Textarea",\r\n
FormProp\t\t\t: "Ciri-ciri Borang",\r\n
\r\n
FontFormats\t\t\t: "Normal;Telah Diformat;Alamat;Heading 1;Heading 2;Heading 3;Heading 4;Heading 5;Heading 6;Perenggan (DIV)",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "Memproses XHTML. Sila tunggu...",\r\n
Done\t\t\t\t: "Siap",\r\n
PasteWordConfirm\t: "Text yang anda hendak tampal adalah berasal dari Word. Adakah anda mahu membuang semua format Word sebelum tampal ke dalam text?",\r\n
NotCompatiblePaste\t: "Arahan ini bole dilakukan jika anda mempuunyai Internet Explorer version 5.5 atau yang lebih tinggi. Adakah anda hendak tampal text tanpa membuang format Word?",\r\n
UnknownToolbarItem\t: "Toolbar item tidak diketahui\\"%1\\"",\r\n
UnknownCommand\t\t: "Arahan tidak diketahui \\"%1\\"",\r\n
NotImplemented\t\t: "Arahan tidak terdapat didalam sistem",\r\n
UnknownToolbarSet\t: "Set toolbar \\"%1\\" tidak wujud",\r\n
NoActiveX\t\t\t: "Your browser\'s security settings could limit some features of the editor. You must enable the option \\"Run ActiveX controls and plug-ins\\". You may experience errors and notice missing features.",\t//MISSING\r\n
BrowseServerBlocked : "The resources browser could not be opened. Make sure that all popup blockers are disabled.",\t//MISSING\r\n
DialogBlocked\t\t: "It was not possible to open the dialog window. Make sure all popup blockers are disabled.",\t//MISSING\r\n
VisitLinkBlocked\t: "It was not possible to open a new window. Make sure all popup blockers are disabled.",\t//MISSING\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "OK",\r\n
DlgBtnCancel\t\t: "Batal",\r\n
DlgBtnClose\t\t\t: "Tutup",\r\n
DlgBtnBrowseServer\t: "Browse Server",\r\n
DlgAdvancedTag\t\t: "Advanced",\r\n
DlgOpOther\t\t\t: "<Lain-lain>",\r\n
DlgInfoTab\t\t\t: "Info",\t//MISSING\r\n
DlgAlertUrl\t\t\t: "Please insert the URL",\t//MISSING\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<tidak di set>",\r\n
DlgGenId\t\t\t: "Id",\r\n
DlgGenLangDir\t\t: "Arah Tulisan",\r\n
DlgGenLangDirLtr\t: "Kiri ke Kanan (LTR)",\r\n
DlgGenLangDirRtl\t: "Kanan ke Kiri (RTL)",\r\n
DlgGenLangCode\t\t: "Kod Bahasa",\r\n
DlgGenAccessKey\t\t: "Kunci Akses",\r\n
DlgGenName\t\t\t: "Nama",\r\n
DlgGenTabIndex\t\t: "Indeks Tab ",\r\n
DlgGenLongDescr\t\t: "Butiran Panjang URL",\r\n
DlgGenClass\t\t\t: "Kelas-kelas Stylesheet",\r\n
DlgGenTitle\t\t\t: "Tajuk Makluman",\r\n
DlgGenContType\t\t: "Jenis Kandungan Makluman",\r\n
DlgGenLinkCharset\t: "Linked Resource Charset",\r\n
DlgGenStyle\t\t\t: "Stail",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Ciri-ciri Imej",\r\n
DlgImgInfoTab\t\t: "Info Imej",\r\n
DlgImgBtnUpload\t\t: "Hantar ke Server",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "Muat Naik",\r\n
DlgImgAlt\t\t\t: "Text Alternatif",\r\n
DlgImgWidth\t\t\t: "Lebar",\r\n
DlgImgHeight\t\t: "Tinggi",\r\n
DlgImgLockRatio\t\t: "Tetapkan Nisbah",\r\n
DlgBtnResetSize\t\t: "Saiz Set Semula",\r\n
DlgImgBorder\t\t: "Border",\r\n
DlgImgHSpace\t\t: "Ruang Melintang",\r\n
DlgImgVSpace\t\t: "Ruang Menegak",\r\n
DlgImgAlign\t\t\t: "Jajaran",\r\n
DlgImgAlignLeft\t\t: "Kiri",\r\n
DlgImgAlignAbsBottom: "Bawah Mutlak",\r\n
DlgImgAlignAbsMiddle: "Pertengahan Mutlak",\r\n
DlgImgAlignBaseline\t: "Garis Dasar",\r\n
DlgImgAlignBottom\t: "Bawah",\r\n
DlgImgAlignMiddle\t: "Pertengahan",\r\n
DlgImgAlignRight\t: "Kanan",\r\n
DlgImgAlignTextTop\t: "Atas Text",\r\n
DlgImgAlignTop\t\t: "Atas",\r\n
DlgImgPreview\t\t: "Prebiu",\r\n
DlgImgAlertUrl\t\t: "Sila taip URL untuk fail gambar",\r\n
DlgImgLinkTab\t\t: "Sambungan",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Flash Properties",\t//MISSING\r\n
DlgFlashChkPlay\t\t: "Auto Play",\t//MISSING\r\n
DlgFlashChkLoop\t\t: "Loop",\t//MISSING\r\n
DlgFlashChkMenu\t\t: "Enable Flash Menu",\t//MISSING\r\n
DlgFlashScale\t\t: "Scale",\t//MISSING\r\n
DlgFlashScaleAll\t: "Show all",\t//MISSING\r\n
DlgFlashScaleNoBorder\t: "No Border",\t//MISSING\r\n
DlgFlashScaleFit\t: "Exact Fit",\t//MISSING\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Sambungan",\r\n
DlgLnkInfoTab\t\t: "Butiran Sambungan",\r\n
DlgLnkTargetTab\t\t: "Sasaran",\r\n
\r\n
DlgLnkType\t\t\t: "Jenis Sambungan",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Pautan dalam muka surat ini",\r\n
DlgLnkTypeEMail\t\t: "E-Mail",\r\n
DlgLnkProto\t\t\t: "Protokol",\r\n
DlgLnkProtoOther\t: "<lain-lain>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Sila pilih pautan",\r\n
DlgLnkAnchorByName\t: "dengan menggunakan nama pautan",\r\n
DlgLnkAnchorById\t: "dengan menggunakan ID elemen",\r\n
DlgLnkNoAnchors\t\t: "(Tiada pautan terdapat dalam dokumen ini)",\r\n
DlgLnkEMail\t\t\t: "Alamat E-Mail",\r\n
DlgLnkEMailSubject\t: "Subjek Mesej",\r\n
DlgLnkEMailBody\t\t: "Isi Kandungan Mesej",\r\n
DlgLnkUpload\t\t: "Muat Naik",\r\n
DlgLnkBtnUpload\t\t: "Hantar ke Server",\r\n
\r\n
DlgLnkTarget\t\t: "Sasaran",\r\n
DlgLnkTargetFrame\t: "<bingkai>",\r\n
DlgLnkTargetPopup\t: "<tetingkap popup>",\r\n
DlgLnkTargetBlank\t: "Tetingkap Baru (_blank)",\r\n
DlgLnkTargetParent\t: "Tetingkap Parent (_parent)",\r\n
DlgLnkTargetSelf\t: "Tetingkap yang Sama (_self)",\r\n
DlgLnkTargetTop\t\t: "Tetingkap yang paling atas (_top)",\r\n
DlgLnkTargetFrameName\t: "Nama Bingkai Sasaran",\r\n
DlgLnkPopWinName\t: "Nama Tetingkap Popup",\r\n
DlgLnkPopWinFeat\t: "Ciri Tetingkap Popup",\r\n
DlgLnkPopResize\t\t: "Saiz bolehubah",\r\n
DlgLnkPopLocation\t: "Bar Lokasi",\r\n
DlgLnkPopMenu\t\t: "Bar Menu",\r\n
DlgLnkPopScroll\t\t: "Bar-bar skrol",\r\n
DlgLnkPopStatus\t\t: "Bar Status",\r\n
DlgLnkPopToolbar\t: "Toolbar",\r\n
DlgLnkPopFullScrn\t: "Skrin Penuh (IE)",\r\n
DlgLnkPopDependent\t: "Bergantungan (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Lebar",\r\n
DlgLnkPopHeight\t\t: "Tinggi",\r\n
DlgLnkPopLeft\t\t: "Posisi Kiri",\r\n
DlgLnkPopTop\t\t: "Posisi Atas",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Sila taip sambungan URL",\r\n
DlnLnkMsgNoEMail\t: "Sila taip alamat e-mail",\r\n
DlnLnkMsgNoAnchor\t: "Sila pilih pautan berkenaaan",\r\n
DlnLnkMsgInvPopName\t: "The popup name must begin with an alphabetic character and must not contain spaces",\t//MISSING\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Pilihan Warna",\r\n
DlgColorBtnClear\t: "Nyahwarna",\r\n
DlgColorHighlight\t: "Terang",\r\n
DlgColorSelected\t: "Dipilih",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Masukkan Smiley",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Sila pilih huruf istimewa",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Ciri-ciri Jadual",\r\n
DlgTableRows\t\t: "Barisan",\r\n
DlgTableColumns\t\t: "Jaluran",\r\n
DlgTableBorder\t\t: "Saiz Border",\r\n
DlgTableAlign\t\t: "Penjajaran",\r\n
DlgTableAlignNotSet\t: "<Tidak diset>",\r\n
DlgTableAlignLeft\t: "Kiri",\r\n
DlgTableAlignCenter\t: "Tengah",\r\n
DlgTableAlignRight\t: "Kanan",\r\n
DlgTableWidth\t\t: "Lebar",\r\n
DlgTableWidthPx\t\t: "piksel-piksel",\r\n
DlgTableWidthPc\t\t: "peratus",\r\n
DlgTableHeight\t\t: "Tinggi",\r\n
DlgTableCellSpace\t: "Ruangan Antara Sel",\r\n
DlgTableCellPad\t\t: "Tambahan Ruang Sel",\r\n
DlgTableCaption\t\t: "Keterangan",\r\n
DlgTableSummary\t\t: "Summary",\t//MISSING\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Ciri-ciri Sel",\r\n
DlgCellWidth\t\t: "Lebar",\r\n
DlgCellWidthPx\t\t: "piksel-piksel",\r\n
DlgCellWidthPc\t\t: "peratus",\r\n
DlgCellHeight\t\t: "Tinggi",\r\n
DlgCellWordWrap\t\t: "Mengulung Perkataan",\r\n
DlgCellWordWrapNotSet\t: "<Tidak diset>",\r\n
DlgCellWordWrapYes\t: "Ya",\r\n
DlgCellWordWrapNo\t: "Tidak",\r\n
DlgCellHorAlign\t\t: "Jajaran Membujur",\r\n
DlgCellHorAlignNotSet\t: "<Tidak diset>",\r\n
DlgCellHorAlignLeft\t: "Kiri",\r\n
DlgCellHorAlignCenter\t: "Tengah",\r\n
DlgCellHorAlignRight: "Kanan",\r\n
DlgCellVerAlign\t\t: "Jajaran Menegak",\r\n
DlgCellVerAlignNotSet\t: "<Tidak diset>",\r\n
DlgCellVerAlignTop\t: "Atas",\r\n
DlgCellVerAlignMiddle\t: "Tengah",\r\n
DlgCellVerAlignBottom\t: "Bawah",\r\n
DlgCellVerAlignBaseline\t: "Garis Dasar",\r\n
DlgCellType\t\t: "Cell Type",\t//MISSING\r\n
DlgCellTypeData\t\t: "Data",\t//MISSING\r\n
DlgCellTypeHeader\t: "Header",\t//MISSING\r\n
DlgCellRowSpan\t\t: "Penggunaan Baris",\r\n
DlgCellCollSpan\t\t: "Penggunaan Lajur",\r\n
DlgCellBackColor\t: "Warna Latarbelakang",\r\n
DlgCellBorderColor\t: "Warna Border",\r\n
DlgCellBtnSelect\t: "Pilih...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Find and Replace",\t//MISSING\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Carian",\r\n
DlgFindFindBtn\t\t: "Cari",\r\n
DlgFindNotFoundMsg\t: "Text yang dicari tidak dijumpai.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Gantian",\r\n
DlgReplaceFindLbl\t\t: "Perkataan yang dicari:",\r\n
DlgReplaceReplaceLbl\t: "Diganti dengan:",\r\n
DlgReplaceCaseChk\t\t: "Padanan case huruf",\r\n
DlgReplaceReplaceBtn\t: "Ganti",\r\n
DlgReplaceReplAllBtn\t: "Ganti semua",\r\n
DlgReplaceWordChk\t\t: "Padana Keseluruhan perkataan",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "Keselamatan perisian browser anda tidak membenarkan operasi suntingan text/imej. Sila gunakan papan kekunci (Ctrl+X).",\r\n
PasteErrorCopy\t: "Keselamatan perisian browser anda tidak membenarkan operasi salinan text/imej. Sila gunakan papan kekunci (Ctrl+C).",\r\n
\r\n
PasteAsText\t\t: "Tampal sebagai text biasa",\r\n
PasteFromWord\t: "Tampal dari perisian \\"Word\\"",\r\n
\r\n
DlgPasteMsg2\t: "Please paste inside the following box using the keyboard (<strong>Ctrl+V</strong>) and hit <strong>OK</strong>.",\t//MISSING\r\n
DlgPasteSec\t\t: "Because of your browser security settings, the editor is not able to access your clipboard data directly. You are required to paste it again in this window.",\t//MISSING\r\n
DlgPasteIgnoreFont\t\t: "Ignore Font Face definitions",\t//MISSING\r\n
DlgPasteRemoveStyles\t: "Remove Styles definitions",\t//MISSING\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Otomatik",\r\n
ColorMoreColors\t: "Warna lain-lain...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Ciri-ciri dokumen",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Ciri-ciri Pautan",\r\n
DlgAnchorName\t\t: "Nama Pautan",\r\n
DlgAnchorErrorName\t: "Sila taip nama pautan",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Tidak terdapat didalam kamus",\r\n
DlgSpellChangeTo\t\t: "Tukarkan kepada",\r\n
DlgSpellBtnIgnore\t\t: "Biar",\r\n
DlgSpellBtnIgnoreAll\t: "Biarkan semua",\r\n
DlgSpellBtnReplace\t\t: "Ganti",\r\n
DlgSpellBtnReplaceAll\t: "Gantikan Semua",\r\n
DlgSpellBtnUndo\t\t\t: "Batalkan",\r\n
DlgSpellNoSuggestions\t: "- Tiada cadangan -",\r\n
DlgSpellProgress\t\t: "Pemeriksaan ejaan sedang diproses...",\r\n
DlgSpellNoMispell\t\t: "Pemeriksaan ejaan siap: Tiada salah ejaan",\r\n
DlgSpellNoChanges\t\t: "Pemeriksaan ejaan siap: Tiada perkataan diubah",\r\n
DlgSpellOneChange\t\t: "Pemeriksaan ejaan siap: Satu perkataan telah diubah",\r\n
DlgSpellManyChanges\t\t: "Pemeriksaan ejaan siap: %1 perkataan diubah",\r\n
\r\n
IeSpellDownload\t\t\t: "Pemeriksa ejaan tidak dipasang. Adakah anda mahu muat turun sekarang?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Teks (Nilai)",\r\n
DlgButtonType\t\t: "Jenis",\r\n
DlgButtonTypeBtn\t: "Button",\t//MISSING\r\n
DlgButtonTypeSbm\t: "Submit",\t//MISSING\r\n
DlgButtonTypeRst\t: "Reset",\t//MISSING\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Nama",\r\n
DlgCheckboxValue\t: "Nilai",\r\n
DlgCheckboxSelected\t: "Dipilih",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Nama",\r\n
DlgFormAction\t: "Tindakan borang",\r\n
DlgFormMethod\t: "Cara borang dihantar",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Nama",\r\n
DlgSelectValue\t\t: "Nilai",\r\n
DlgSelectSize\t\t: "Saiz",\r\n
DlgSelectLines\t\t: "garisan",\r\n
DlgSelectChkMulti\t: "Benarkan pilihan pelbagai",\r\n
DlgSelectOpAvail\t: "Pilihan sediada",\r\n
DlgSelectOpText\t\t: "Teks",\r\n
DlgSelectOpValue\t: "Nilai",\r\n
DlgSelectBtnAdd\t\t: "Tambah Pilihan",\r\n
DlgSelectBtnModify\t: "Ubah Pilihan",\r\n
DlgSelectBtnUp\t\t: "Naik ke atas",\r\n
DlgSelectBtnDown\t: "Turun ke bawah",\r\n
DlgSelectBtnSetValue : "Set sebagai nilai terpilih",\r\n
DlgSelectBtnDelete\t: "Padam",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Nama",\r\n
DlgTextareaCols\t: "Lajur",\r\n
DlgTextareaRows\t: "Baris",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Nama",\r\n
DlgTextValue\t\t: "Nilai",\r\n
DlgTextCharWidth\t: "Lebar isian",\r\n
DlgTextMaxChars\t\t: "Isian Maksimum",\r\n
DlgTextType\t\t\t: "Jenis",\r\n
DlgTextTypeText\t\t: "Teks",\r\n
DlgTextTypePass\t\t: "Kata Laluan",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Nama",\r\n
DlgHiddenValue\t: "Nilai",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Ciri-ciri senarai berpeluru",\r\n
NumberedListProp\t: "Ciri-ciri senarai bernombor",\r\n
DlgLstStart\t\t\t: "Start",\t//MISSING\r\n
DlgLstType\t\t\t: "Jenis",\r\n
DlgLstTypeCircle\t: "Circle",\r\n
DlgLstTypeDisc\t\t: "Disc",\t//MISSING\r\n
DlgLstTypeSquare\t: "Square",\r\n
DlgLstTypeNumbers\t: "Nombor-nombor (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Huruf-huruf kecil (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Huruf-huruf besar (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Nombor Roman Kecil (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Nombor Roman Besar (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Umum",\r\n
DlgDocBackTab\t\t: "Latarbelakang",\r\n
DlgDocColorsTab\t\t: "Warna dan margin",\r\n
DlgDocMetaTab\t\t: "Data Meta",\r\n
\r\n
DlgDocPageTitle\t\t: "Tajuk Muka Surat",\r\n
DlgDocLangDir\t\t: "Arah Tulisan",\r\n
DlgDocLangDirLTR\t: "Kiri ke Kanan (LTR)",\r\n
DlgDocLangDirRTL\t: "Kanan ke Kiri (RTL)",\r\n
DlgDocLangCode\t\t: "Kod Bahasa",\r\n
DlgDocCharSet\t\t: "Enkod Set Huruf",\r\n
DlgDocCharSetCE\t\t: "Central European",\t//MISSING\r\n
DlgDocCharSetCT\t\t: "Chinese Traditional (Big5)",\t//MISSING\r\n
DlgDocCharSetCR\t\t: "Cyrillic",\t//MISSING\r\n
DlgDocCharSetGR\t\t: "Greek",\t//MISSING\r\n
DlgDocCharSetJP\t\t: "Japanese",\t//MISSING\r\n
DlgDocCharSetKR\t\t: "Korean",\t//MISSING\r\n
DlgDocCharSetTR\t\t: "Turkish",\t//MISSING\r\n
DlgDocCharSetUN\t\t: "Unicode (UTF-8)",\t//MISSING\r\n
DlgDocCharSetWE\t\t: "Western European",\t//MISSING\r\n
DlgDocCharSetOther\t: "Enkod Set Huruf yang Lain",\r\n
\r\n
DlgDocDocType\t\t: "Jenis Kepala Dokumen",\r\n
DlgDocDocTypeOther\t: "Jenis Kepala Dokumen yang Lain",\r\n
DlgDocIncXHTML\t\t: "Masukkan pemula kod XHTML",\r\n
DlgDocBgColor\t\t: "Warna Latarbelakang",\r\n
DlgDocBgImage\t\t: "URL Gambar Latarbelakang",\r\n
DlgDocBgNoScroll\t: "Imej Latarbelakang tanpa Skrol",\r\n
DlgDocCText\t\t\t: "Teks",\r\n
DlgDocCLink\t\t\t: "Sambungan",\r\n
DlgDocCVisited\t\t: "Sambungan telah Dilawati",\r\n
DlgDocCActive\t\t: "Sambungan Aktif",\r\n
DlgDocMargins\t\t: "Margin Muka Surat",\r\n
DlgDocMaTop\t\t\t: "Atas",\r\n
DlgDocMaLeft\t\t: "Kiri",\r\n
DlgDocMaRight\t\t: "Kanan",\r\n
DlgDocMaBottom\t\t: "Bawah",\r\n
DlgDocMeIndex\t\t: "Kata Kunci Indeks Dokumen (dipisahkan oleh koma)",\r\n
DlgDocMeDescr\t\t: "Keterangan Dokumen",\r\n
DlgDocMeAuthor\t\t: "Penulis",\r\n
DlgDocMeCopy\t\t: "Hakcipta",\r\n
DlgDocPreview\t\t: "Prebiu",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Templat",\r\n
DlgTemplatesTitle\t: "Templat Kandungan",\r\n
DlgTemplatesSelMsg\t: "Sila pilih templat untuk dibuka oleh editor<br>(kandungan sebenar akan hilang):",\r\n
DlgTemplatesLoading\t: "Senarai Templat sedang diproses. Sila Tunggu...",\r\n
DlgTemplatesNoTpl\t: "(Tiada Templat Disimpan)",\r\n
DlgTemplatesReplace\t: "Replace actual contents",\t//MISSING\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Tentang",\r\n
DlgAboutBrowserInfoTab\t: "Maklumat Perisian Browser",\r\n
DlgAboutLicenseTab\t: "License",\t//MISSING\r\n
DlgAboutVersion\t\t: "versi",\r\n
DlgAboutInfo\t\t: "Untuk maklumat lanjut sila pergi ke",\r\n
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
            <value> <int>19492</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
