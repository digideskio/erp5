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
            <value> <string>tr.js</string> </value>
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
 * Turkish language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Araç Çubuğunu Kapat",\r\n
ToolbarExpand\t\t: "Araç Çubuğunu Aç",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Kaydet",\r\n
NewPage\t\t\t\t: "Yeni Sayfa",\r\n
Preview\t\t\t\t: "Ön İzleme",\r\n
Cut\t\t\t\t\t: "Kes",\r\n
Copy\t\t\t\t: "Kopyala",\r\n
Paste\t\t\t\t: "Yapıştır",\r\n
PasteText\t\t\t: "Düzyazı Olarak Yapıştır",\r\n
PasteWord\t\t\t: "Word\'den Yapıştır",\r\n
Print\t\t\t\t: "Yazdır",\r\n
SelectAll\t\t\t: "Tümünü Seç",\r\n
RemoveFormat\t\t: "Biçimi Kaldır",\r\n
InsertLinkLbl\t\t: "Köprü",\r\n
InsertLink\t\t\t: "Köprü Ekle/Düzenle",\r\n
RemoveLink\t\t\t: "Köprü Kaldır",\r\n
VisitLink\t\t\t: "Köprü Aç",\r\n
Anchor\t\t\t\t: "Çapa Ekle/Düzenle",\r\n
AnchorDelete\t\t: "Çapa Sil",\r\n
InsertImageLbl\t\t: "Resim",\r\n
InsertImage\t\t\t: "Resim Ekle/Düzenle",\r\n
InsertFlashLbl\t\t: "Flash",\r\n
InsertFlash\t\t\t: "Flash Ekle/Düzenle",\r\n
InsertTableLbl\t\t: "Tablo",\r\n
InsertTable\t\t\t: "Tablo Ekle/Düzenle",\r\n
InsertLineLbl\t\t: "Satır",\r\n
InsertLine\t\t\t: "Yatay Satır Ekle",\r\n
InsertSpecialCharLbl: "Özel Karakter",\r\n
InsertSpecialChar\t: "Özel Karakter Ekle",\r\n
InsertSmileyLbl\t\t: "İfade",\r\n
InsertSmiley\t\t: "İfade Ekle",\r\n
About\t\t\t\t: "FCKeditor Hakkında",\r\n
Bold\t\t\t\t: "Kalın",\r\n
Italic\t\t\t\t: "İtalik",\r\n
Underline\t\t\t: "Altı Çizgili",\r\n
StrikeThrough\t\t: "Üstü Çizgili",\r\n
Subscript\t\t\t: "Alt Simge",\r\n
Superscript\t\t\t: "Üst Simge",\r\n
LeftJustify\t\t\t: "Sola Dayalı",\r\n
CenterJustify\t\t: "Ortalanmış",\r\n
RightJustify\t\t: "Sağa Dayalı",\r\n
BlockJustify\t\t: "İki Kenara Yaslanmış",\r\n
DecreaseIndent\t\t: "Sekme Azalt",\r\n
IncreaseIndent\t\t: "Sekme Arttır",\r\n
Blockquote\t\t\t: "Blok Oluştur",\r\n
CreateDiv\t\t\t: "Div Ekle",\r\n
EditDiv\t\t\t\t: "Div Düzenle",\r\n
DeleteDiv\t\t\t: "Div Sil",\r\n
Undo\t\t\t\t: "Geri Al",\r\n
Redo\t\t\t\t: "Tekrarla",\r\n
NumberedListLbl\t\t: "Numaralı Liste",\r\n
NumberedList\t\t: "Numaralı Liste Ekle/Kaldır",\r\n
BulletedListLbl\t\t: "Simgeli Liste",\r\n
BulletedList\t\t: "Simgeli Liste Ekle/Kaldır",\r\n
ShowTableBorders\t: "Tablo Kenarlarını Göster",\r\n
ShowDetails\t\t\t: "Detayları Göster",\r\n
Style\t\t\t\t: "Biçem",\r\n
FontFormat\t\t\t: "Biçim",\r\n
Font\t\t\t\t: "Yazı Türü",\r\n
FontSize\t\t\t: "Boyut",\r\n
TextColor\t\t\t: "Yazı Rengi",\r\n
BGColor\t\t\t\t: "Arka Renk",\r\n
Source\t\t\t\t: "Kaynak",\r\n
Find\t\t\t\t: "Bul",\r\n
Replace\t\t\t\t: "Değiştir",\r\n
SpellCheck\t\t\t: "Yazım Denetimi",\r\n
UniversalKeyboard\t: "Evrensel Klavye",\r\n
PageBreakLbl\t\t: "Sayfa sonu",\r\n
PageBreak\t\t\t: "Sayfa Sonu Ekle",\r\n
\r\n
Form\t\t\t: "Form",\r\n
Checkbox\t\t: "Onay Kutusu",\r\n
RadioButton\t\t: "Seçenek Düğmesi",\r\n
TextField\t\t: "Metin Girişi",\r\n
Textarea\t\t: "Çok Satırlı Metin",\r\n
HiddenField\t\t: "Gizli Veri",\r\n
Button\t\t\t: "Düğme",\r\n
SelectionField\t: "Seçim Menüsü",\r\n
ImageButton\t\t: "Resimli Düğme",\r\n
\r\n
FitWindow\t\t: "Düzenleyici boyutunu büyüt",\r\n
ShowBlocks\t\t: "Blokları Göster",\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Köprü Düzenle",\r\n
CellCM\t\t\t\t: "Hücre",\r\n
RowCM\t\t\t\t: "Satır",\r\n
ColumnCM\t\t\t: "Sütun",\r\n
InsertRowAfter\t\t: "Satır Ekle - Sonra",\r\n
InsertRowBefore\t\t: "Satır Ekle - Önce",\r\n
DeleteRows\t\t\t: "Satır Sil",\r\n
InsertColumnAfter\t: "Kolon Ekle - Sonra",\r\n
InsertColumnBefore\t: "Kolon Ekle - Önce",\r\n
DeleteColumns\t\t: "Sütun Sil",\r\n
InsertCellAfter\t\t: "Hücre Ekle - Sonra",\r\n
InsertCellBefore\t: "Hücre Ekle - Önce",\r\n
DeleteCells\t\t\t: "Hücre Sil",\r\n
MergeCells\t\t\t: "Hücreleri Birleştir",\r\n
MergeRight\t\t\t: "Birleştir - Sağdaki İle ",\r\n
MergeDown\t\t\t: "Birleştir - Aşağıdaki İle ",\r\n
HorizontalSplitCell\t: "Hücreyi Yatay Böl",\r\n
VerticalSplitCell\t: "Hücreyi Dikey Böl",\r\n
TableDelete\t\t\t: "Tabloyu Sil",\r\n
CellProperties\t\t: "Hücre Özellikleri",\r\n
TableProperties\t\t: "Tablo Özellikleri",\r\n
ImageProperties\t\t: "Resim Özellikleri",\r\n
FlashProperties\t\t: "Flash Özellikleri",\r\n
\r\n
AnchorProp\t\t\t: "Çapa Özellikleri",\r\n
ButtonProp\t\t\t: "Düğme Özellikleri",\r\n
CheckboxProp\t\t: "Onay Kutusu Özellikleri",\r\n
HiddenFieldProp\t\t: "Gizli Veri Özellikleri",\r\n
RadioButtonProp\t\t: "Seçenek Düğmesi Özellikleri",\r\n
ImageButtonProp\t\t: "Resimli Düğme Özellikleri",\r\n
TextFieldProp\t\t: "Metin Girişi Özellikleri",\r\n
SelectionFieldProp\t: "Seçim Menüsü Özellikleri",\r\n
TextareaProp\t\t: "Çok Satırlı Metin Özellikleri",\r\n
FormProp\t\t\t: "Form Özellikleri",\r\n
\r\n
FontFormats\t\t\t: "Normal;Biçimli;Adres;Başlık 1;Başlık 2;Başlık 3;Başlık 4;Başlık 5;Başlık 6;Paragraf (DIV)",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "XHTML işleniyor. Lütfen bekleyin...",\r\n
Done\t\t\t\t: "Bitti",\r\n
PasteWordConfirm\t: "Yapıştırdığınız yazı Word\'den gelmişe benziyor. Yapıştırmadan önce gereksiz eklentileri silmek ister misiniz?",\r\n
NotCompatiblePaste\t: "Bu komut Internet Explorer 5.5 ve ileriki sürümleri için mevcuttur. Temizlenmeden yapıştırılmasını ister misiniz ?",\r\n
UnknownToolbarItem\t: "Bilinmeyen araç çubugu öğesi \\"%1\\"",\r\n
UnknownCommand\t\t: "Bilinmeyen komut \\"%1\\"",\r\n
NotImplemented\t\t: "Komut uyarlanamadı",\r\n
UnknownToolbarSet\t: "\\"%1\\" araç çubuğu öğesi mevcut değil",\r\n
NoActiveX\t\t\t: "Kullandığınız tarayıcının güvenlik ayarları bazı özelliklerin kullanılmasını engelliyor. Bu özelliklerin çalışması için \\"Run ActiveX controls and plug-ins (Activex ve eklentileri çalıştır)\\" seçeneğinin aktif yapılması gerekiyor. Kullanılamayan eklentiler ve hatalar konusunda daha fazla bilgi sahibi olun.",\r\n
BrowseServerBlocked : "Kaynak tarayıcısı açılamadı. Tüm \\"popup blocker\\" programlarının devre dışı olduğundan emin olun. (Yahoo toolbar, Msn toolbar, Google toolbar gibi)",\r\n
DialogBlocked\t\t: "Diyalog açmak mümkün olmadı. Tüm \\"Popup Blocker\\" programlarının devre dışı olduğundan emin olun.",\r\n
VisitLinkBlocked\t: "Yeni pencere açmak mümkün olmadı. Tüm \\"Popup Blocker\\" programlarının devre dışı olduğundan emin olun",\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "Tamam",\r\n
DlgBtnCancel\t\t: "İptal",\r\n
DlgBtnClose\t\t\t: "Kapat",\r\n
DlgBtnBrowseServer\t: "Sunucuyu Gez",\r\n
DlgAdvancedTag\t\t: "Gelişmiş",\r\n
DlgOpOther\t\t\t: "<Diğer>",\r\n
DlgInfoTab\t\t\t: "Bilgi",\r\n
DlgAlertUrl\t\t\t: "Lütfen URL girin",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<tanımlanmamış>",\r\n
DlgGenId\t\t\t: "Kimlik",\r\n
DlgGenLangDir\t\t: "Dil Yönü",\r\n
DlgGenLangDirLtr\t: "Soldan Sağa (LTR)",\r\n
DlgGenLangDirRtl\t: "Sağdan Sola (RTL)",\r\n
DlgGenLangCode\t\t: "Dil Kodlaması",\r\n
DlgGenAccessKey\t\t: "Erişim Tuşu",\r\n
DlgGenName\t\t\t: "Ad",\r\n
DlgGenTabIndex\t\t: "Sekme İndeksi",\r\n
DlgGenLongDescr\t\t: "Uzun Tanımlı URL",\r\n
DlgGenClass\t\t\t: "Biçem Sayfası Sınıfları",\r\n
DlgGenTitle\t\t\t: "Danışma Başlığı",\r\n
DlgGenContType\t\t: "Danışma İçerik Türü",\r\n
DlgGenLinkCharset\t: "Bağlı Kaynak Karakter Gurubu",\r\n
DlgGenStyle\t\t\t: "Biçem",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Resim Özellikleri",\r\n
DlgImgInfoTab\t\t: "Resim Bilgisi",\r\n
DlgImgBtnUpload\t\t: "Sunucuya Yolla",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "Karşıya Yükle",\r\n
DlgImgAlt\t\t\t: "Alternatif Yazı",\r\n
DlgImgWidth\t\t\t: "Genişlik",\r\n
DlgImgHeight\t\t: "Yükseklik",\r\n
DlgImgLockRatio\t\t: "Oranı Kilitle",\r\n
DlgBtnResetSize\t\t: "Boyutu Başa Döndür",\r\n
DlgImgBorder\t\t: "Kenar",\r\n
DlgImgHSpace\t\t: "Yatay Boşluk",\r\n
DlgImgVSpace\t\t: "Dikey Boşluk",\r\n
DlgImgAlign\t\t\t: "Hizalama",\r\n
DlgImgAlignLeft\t\t: "Sol",\r\n
DlgImgAlignAbsBottom: "Tam Altı",\r\n
DlgImgAlignAbsMiddle: "Tam Ortası",\r\n
DlgImgAlignBaseline\t: "Taban Çizgisi",\r\n
DlgImgAlignBottom\t: "Alt",\r\n
DlgImgAlignMiddle\t: "Orta",\r\n
DlgImgAlignRight\t: "Sağ",\r\n
DlgImgAlignTextTop\t: "Yazı Tepeye",\r\n
DlgImgAlignTop\t\t: "Tepe",\r\n
DlgImgPreview\t\t: "Ön İzleme",\r\n
DlgImgAlertUrl\t\t: "Lütfen resmin URL\'sini yazınız",\r\n
DlgImgLinkTab\t\t: "Köprü",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Flash Özellikleri",\r\n
DlgFlashChkPlay\t\t: "Otomatik Oynat",\r\n
DlgFlashChkLoop\t\t: "Döngü",\r\n
DlgFlashChkMenu\t\t: "Flash Menüsünü Kullan",\r\n
DlgFlashScale\t\t: "Boyutlandır",\r\n
DlgFlashScaleAll\t: "Hepsini Göster",\r\n
DlgFlashScaleNoBorder\t: "Kenar Yok",\r\n
DlgFlashScaleFit\t: "Tam Sığdır",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Köprü",\r\n
DlgLnkInfoTab\t\t: "Köprü Bilgisi",\r\n
DlgLnkTargetTab\t\t: "Hedef",\r\n
\r\n
DlgLnkType\t\t\t: "Köprü Türü",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Bu sayfada çapa",\r\n
DlgLnkTypeEMail\t\t: "E-Posta",\r\n
DlgLnkProto\t\t\t: "Protokol",\r\n
DlgLnkProtoOther\t: "<diğer>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Çapa Seç",\r\n
DlgLnkAnchorByName\t: "Çapa Adı ile",\r\n
DlgLnkAnchorById\t: "Eleman Kimlik Numarası ile",\r\n
DlgLnkNoAnchors\t\t: "(Bu belgede hiç çapa yok)",\r\n
DlgLnkEMail\t\t\t: "E-Posta Adresi",\r\n
DlgLnkEMailSubject\t: "İleti Konusu",\r\n
DlgLnkEMailBody\t\t: "İleti Gövdesi",\r\n
DlgLnkUpload\t\t: "Karşıya Yükle",\r\n
DlgLnkBtnUpload\t\t: "Sunucuya Gönder",\r\n
\r\n
DlgLnkTarget\t\t: "Hedef",\r\n
DlgLnkTargetFrame\t: "<çerçeve>",\r\n
DlgLnkTargetPopup\t: "<yeni açılan pencere>",\r\n
DlgLnkTargetBlank\t: "Yeni Pencere(_blank)",\r\n
DlgLnkTargetParent\t: "Anne Pencere (_parent)",\r\n
DlgLnkTargetSelf\t: "Kendi Penceresi (_self)",\r\n
DlgLnkTargetTop\t\t: "En Üst Pencere (_top)",\r\n
DlgLnkTargetFrameName\t: "Hedef Çerçeve Adı",\r\n
DlgLnkPopWinName\t: "Yeni Açılan Pencere Adı",\r\n
DlgLnkPopWinFeat\t: "Yeni Açılan Pencere Özellikleri",\r\n
DlgLnkPopResize\t\t: "Boyutlandırılabilir",\r\n
DlgLnkPopLocation\t: "Yer Çubuğu",\r\n
DlgLnkPopMenu\t\t: "Menü Çubuğu",\r\n
DlgLnkPopScroll\t\t: "Kaydırma Çubukları",\r\n
DlgLnkPopStatus\t\t: "Durum Çubuğu",\r\n
DlgLnkPopToolbar\t: "Araç Çubuğu",\r\n
DlgLnkPopFullScrn\t: "Tam Ekran (IE)",\r\n
DlgLnkPopDependent\t: "Bağımlı (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Genişlik",\r\n
DlgLnkPopHeight\t\t: "Yükseklik",\r\n
DlgLnkPopLeft\t\t: "Sola Göre Konum",\r\n
DlgLnkPopTop\t\t: "Yukarıya Göre Konum",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Lütfen köprü URL\'sini yazın",\r\n
DlnLnkMsgNoEMail\t: "Lütfen E-posta adresini yazın",\r\n
DlnLnkMsgNoAnchor\t: "Lütfen bir çapa seçin",\r\n
DlnLnkMsgInvPopName\t: "Açılır pencere adı abecesel bir karakterle başlamalı ve boşluk içermemelidir",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Renk Seç",\r\n
DlgColorBtnClear\t: "Temizle",\r\n
DlgColorHighlight\t: "Vurgula",\r\n
DlgColorSelected\t: "Seçilmiş",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "İfade Ekle",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Özel Karakter Seç",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Tablo Özellikleri",\r\n
DlgTableRows\t\t: "Satırlar",\r\n
DlgTableColumns\t\t: "Sütunlar",\r\n
DlgTableBorder\t\t: "Kenar Kalınlığı",\r\n
DlgTableAlign\t\t: "Hizalama",\r\n
DlgTableAlignNotSet\t: "<Tanımlanmamış>",\r\n
DlgTableAlignLeft\t: "Sol",\r\n
DlgTableAlignCenter\t: "Merkez",\r\n
DlgTableAlignRight\t: "Sağ",\r\n
DlgTableWidth\t\t: "Genişlik",\r\n
DlgTableWidthPx\t\t: "piksel",\r\n
DlgTableWidthPc\t\t: "yüzde",\r\n
DlgTableHeight\t\t: "Yükseklik",\r\n
DlgTableCellSpace\t: "Izgara kalınlığı",\r\n
DlgTableCellPad\t\t: "Izgara yazı arası",\r\n
DlgTableCaption\t\t: "Başlık",\r\n
DlgTableSummary\t\t: "Özet",\r\n
DlgTableHeaders\t\t: "Başlıklar",\r\n
DlgTableHeadersNone\t\t: "Yok",\r\n
DlgTableHeadersColumn\t: "İlk Sütun",\r\n
DlgTableHeadersRow\t\t: "İlk Satır",\r\n
DlgTableHeadersBoth\t\t: "Her İkisi",\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Hücre Özellikleri",\r\n
DlgCellWidth\t\t: "Genişlik",\r\n
DlgCellWidthPx\t\t: "piksel",\r\n
DlgCellWidthPc\t\t: "yüzde",\r\n
DlgCellHeight\t\t: "Yükseklik",\r\n
DlgCellWordWrap\t\t: "Sözcük Kaydır",\r\n
DlgCellWordWrapNotSet\t: "<Tanımlanmamış>",\r\n
DlgCellWordWrapYes\t: "Evet",\r\n
DlgCellWordWrapNo\t: "Hayır",\r\n
DlgCellHorAlign\t\t: "Yatay Hizalama",\r\n
DlgCellHorAlignNotSet\t: "<Tanımlanmamış>",\r\n
DlgCellHorAlignLeft\t: "Sol",\r\n
DlgCellHorAlignCenter\t: "Merkez",\r\n
DlgCellHorAlignRight: "Sağ",\r\n
DlgCellVerAlign\t\t: "Dikey Hizalama",\r\n
DlgCellVerAlignNotSet\t: "<Tanımlanmamış>",\r\n
DlgCellVerAlignTop\t: "Tepe",\r\n
DlgCellVerAlignMiddle\t: "Orta",\r\n
DlgCellVerAlignBottom\t: "Alt",\r\n
DlgCellVerAlignBaseline\t: "Taban Çizgisi",\r\n
DlgCellType\t\t: "Hücre Tipi",\r\n
DlgCellTypeData\t\t: "Veri",\r\n
DlgCellTypeHeader\t: "Başlık",\r\n
DlgCellRowSpan\t\t: "Satır Kapla",\r\n
DlgCellCollSpan\t\t: "Sütun Kapla",\r\n
DlgCellBackColor\t: "Arka Plan Rengi",\r\n
DlgCellBorderColor\t: "Kenar Rengi",\r\n
DlgCellBtnSelect\t: "Seç...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Bul ve Değiştir",\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Bul",\r\n
DlgFindFindBtn\t\t: "Bul",\r\n
DlgFindNotFoundMsg\t: "Belirtilen yazı bulunamadı.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Değiştir",\r\n
DlgReplaceFindLbl\t\t: "Aranan:",\r\n
DlgReplaceReplaceLbl\t: "Bununla değiştir:",\r\n
DlgReplaceCaseChk\t\t: "Büyük/küçük harf duyarlı",\r\n
DlgReplaceReplaceBtn\t: "Değiştir",\r\n
DlgReplaceReplAllBtn\t: "Tümünü Değiştir",\r\n
DlgReplaceWordChk\t\t: "Kelimenin tamamı uysun",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "Gezgin yazılımınızın güvenlik ayarları düzenleyicinin otomatik kesme işlemine izin vermiyor. İşlem için (Ctrl+X) tuşlarını kullanın.",\r\n
PasteErrorCopy\t: "Gezgin yazılımınızın güvenlik ayarları düzenleyicinin otomatik kopyalama işlemine izin vermiyor. İşlem için (Ctrl+C) tuşlarını kullanın.",\r\n
\r\n
PasteAsText\t\t: "Düz Metin Olarak Yapıştır",\r\n
PasteFromWord\t: "Word\'den yapıştır",\r\n
\r\n
DlgPasteMsg2\t: "Lütfen aşağıdaki kutunun içine yapıştırın. (<STRONG>Ctrl+V</STRONG>) ve <STRONG>Tamam</STRONG> butonunu tıklayın.",\r\n
DlgPasteSec\t\t: "Gezgin yazılımınızın güvenlik ayarları düzenleyicinin direkt olarak panoya erişimine izin vermiyor. Bu pencere içine tekrar yapıştırmalısınız..",\r\n
DlgPasteIgnoreFont\t\t: "Yazı Tipi tanımlarını yoksay",\r\n
DlgPasteRemoveStyles\t: "Biçem Tanımlarını çıkar",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Otomatik",\r\n
ColorMoreColors\t: "Diğer renkler...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Belge Özellikleri",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Çapa Özellikleri",\r\n
DlgAnchorName\t\t: "Çapa Adı",\r\n
DlgAnchorErrorName\t: "Lütfen çapa için ad giriniz",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Sözlükte Yok",\r\n
DlgSpellChangeTo\t\t: "Şuna değiştir:",\r\n
DlgSpellBtnIgnore\t\t: "Yoksay",\r\n
DlgSpellBtnIgnoreAll\t: "Tümünü Yoksay",\r\n
DlgSpellBtnReplace\t\t: "Değiştir",\r\n
DlgSpellBtnReplaceAll\t: "Tümünü Değiştir",\r\n
DlgSpellBtnUndo\t\t\t: "Geri Al",\r\n
DlgSpellNoSuggestions\t: "- Öneri Yok -",\r\n
DlgSpellProgress\t\t: "Yazım denetimi işlemde...",\r\n
DlgSpellNoMispell\t\t: "Yazım denetimi tamamlandı: Yanlış yazıma rastlanmadı",\r\n
DlgSpellNoChanges\t\t: "Yazım denetimi tamamlandı: Hiçbir kelime değiştirilmedi",\r\n
DlgSpellOneChange\t\t: "Yazım denetimi tamamlandı: Bir kelime değiştirildi",\r\n
DlgSpellManyChanges\t\t: "Yazım denetimi tamamlandı: %1 kelime değiştirildi",\r\n
\r\n
IeSpellDownload\t\t\t: "Yazım denetimi yüklenmemiş. Şimdi yüklemek ister misiniz?",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Metin (Değer)",\r\n
DlgButtonType\t\t: "Tip",\r\n
DlgButtonTypeBtn\t: "Düğme",\r\n
DlgButtonTypeSbm\t: "Gönder",\r\n
DlgButtonTypeRst\t: "Sıfırla",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Ad",\r\n
DlgCheckboxValue\t: "Değer",\r\n
DlgCheckboxSelected\t: "Seçili",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Ad",\r\n
DlgFormAction\t: "İşlem",\r\n
DlgFormMethod\t: "Yöntem",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Ad",\r\n
DlgSelectValue\t\t: "Değer",\r\n
DlgSelectSize\t\t: "Boyut",\r\n
DlgSelectLines\t\t: "satır",\r\n
DlgSelectChkMulti\t: "Çoklu seçime izin ver",\r\n
DlgSelectOpAvail\t: "Mevcut Seçenekler",\r\n
DlgSelectOpText\t\t: "Metin",\r\n
DlgSelectOpValue\t: "Değer",\r\n
DlgSelectBtnAdd\t\t: "Ekle",\r\n
DlgSelectBtnModify\t: "Düzenle",\r\n
DlgSelectBtnUp\t\t: "Yukarı",\r\n
DlgSelectBtnDown\t: "Aşağı",\r\n
DlgSelectBtnSetValue : "Seçili değer olarak ata",\r\n
DlgSelectBtnDelete\t: "Sil",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Ad",\r\n
DlgTextareaCols\t: "Sütunlar",\r\n
DlgTextareaRows\t: "Satırlar",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Ad",\r\n
DlgTextValue\t\t: "Değer",\r\n
DlgTextCharWidth\t: "Karakter Genişliği",\r\n
DlgTextMaxChars\t\t: "En Fazla Karakter",\r\n
DlgTextType\t\t\t: "Tür",\r\n
DlgTextTypeText\t\t: "Metin",\r\n
DlgTextTypePass\t\t: "Parola",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Ad",\r\n
DlgHiddenValue\t: "Değer",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Simgeli Liste Özellikleri",\r\n
NumberedListProp\t: "Numaralı Liste Özellikleri",\r\n
DlgLstStart\t\t\t: "Başlangıç",\r\n
DlgLstType\t\t\t: "Tip",\r\n
DlgLstTypeCircle\t: "Çember",\r\n
DlgLstTypeDisc\t\t: "Disk",\r\n
DlgLstTypeSquare\t: "Kare",\r\n
DlgLstTypeNumbers\t: "Sayılar (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Küçük Harfler (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Büyük Harfler (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Küçük Romen Rakamları (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Büyük Romen Rakamları (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Genel",\r\n
DlgDocBackTab\t\t: "Arka Plan",\r\n
DlgDocColorsTab\t\t: "Renkler ve Kenar Boşlukları",\r\n
DlgDocMetaTab\t\t: "Tanım Bilgisi (Meta)",\r\n
\r\n
DlgDocPageTitle\t\t: "Sayfa Başlığı",\r\n
DlgDocLangDir\t\t: "Dil Yönü",\r\n
DlgDocLangDirLTR\t: "Soldan Sağa (LTR)",\r\n
DlgDocLangDirRTL\t: "Sağdan Sola (RTL)",\r\n
DlgDocLangCode\t\t: "Dil Kodu",\r\n
DlgDocCharSet\t\t: "Karakter Kümesi Kodlaması",\r\n
DlgDocCharSetCE\t\t: "Orta Avrupa",\r\n
DlgDocCharSetCT\t\t: "Geleneksel Çince (Big5)",\r\n
DlgDocCharSetCR\t\t: "Kiril",\r\n
DlgDocCharSetGR\t\t: "Yunanca",\r\n
DlgDocCharSetJP\t\t: "Japonca",\r\n
DlgDocCharSetKR\t\t: "Korece",\r\n
DlgDocCharSetTR\t\t: "Türkçe",\r\n
DlgDocCharSetUN\t\t: "Unicode (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "Batı Avrupa",\r\n
DlgDocCharSetOther\t: "Diğer Karakter Kümesi Kodlaması",\r\n
\r\n
DlgDocDocType\t\t: "Belge Türü Başlığı",\r\n
DlgDocDocTypeOther\t: "Diğer Belge Türü Başlığı",\r\n
DlgDocIncXHTML\t\t: "XHTML Bildirimlerini Dahil Et",\r\n
DlgDocBgColor\t\t: "Arka Plan Rengi",\r\n
DlgDocBgImage\t\t: "Arka Plan Resim URLsi",\r\n
DlgDocBgNoScroll\t: "Sabit Arka Plan",\r\n
DlgDocCText\t\t\t: "Metin",\r\n
DlgDocCLink\t\t\t: "Köprü",\r\n
DlgDocCVisited\t\t: "Ziyaret Edilmiş Köprü",\r\n
DlgDocCActive\t\t: "Etkin Köprü",\r\n
DlgDocMargins\t\t: "Kenar Boşlukları",\r\n
DlgDocMaTop\t\t\t: "Tepe",\r\n
DlgDocMaLeft\t\t: "Sol",\r\n
DlgDocMaRight\t\t: "Sağ",\r\n
DlgDocMaBottom\t\t: "Alt",\r\n
DlgDocMeIndex\t\t: "Belge Dizinleme Anahtar Kelimeleri (virgülle ayrılmış)",\r\n
DlgDocMeDescr\t\t: "Belge Tanımı",\r\n
DlgDocMeAuthor\t\t: "Yazar",\r\n
DlgDocMeCopy\t\t: "Telif",\r\n
DlgDocPreview\t\t: "Ön İzleme",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Şablonlar",\r\n
DlgTemplatesTitle\t: "İçerik Şablonları",\r\n
DlgTemplatesSelMsg\t: "Düzenleyicide açmak için lütfen bir şablon seçin.<br>(hali hazırdaki içerik kaybolacaktır.):",\r\n
DlgTemplatesLoading\t: "Şablon listesi yüklenmekte. Lütfen bekleyiniz...",\r\n
DlgTemplatesNoTpl\t: "(Belirli bir şablon seçilmedi)",\r\n
DlgTemplatesReplace\t: "Mevcut içerik ile değiştir",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Hakkında",\r\n
DlgAboutBrowserInfoTab\t: "Gezgin Bilgisi",\r\n
DlgAboutLicenseTab\t: "Lisans",\r\n
DlgAboutVersion\t\t: "sürüm",\r\n
DlgAboutInfo\t\t: "Daha fazla bilgi için:",\r\n
\r\n
// Div Dialog\r\n
DlgDivGeneralTab\t: "Genel",\r\n
DlgDivAdvancedTab\t: "Gelişmiş",\r\n
DlgDivStyle\t\t: "Sitil",\r\n
DlgDivInlineStyle\t: "Satıriçi Sitil",\r\n
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
            <value> <int>19286</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
