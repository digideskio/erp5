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
            <value> <string>ts83858910.12</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>el.js</string> </value>
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
 * Greek language file.\r\n
 */\r\n
\r\n
var FCKLang =\r\n
{\r\n
// Language direction : "ltr" (left to right) or "rtl" (right to left).\r\n
Dir\t\t\t\t\t: "ltr",\r\n
\r\n
ToolbarCollapse\t\t: "Απόκρυψη Μπάρας Εργαλείων",\r\n
ToolbarExpand\t\t: "Εμφάνιση Μπάρας Εργαλείων",\r\n
\r\n
// Toolbar Items and Context Menu\r\n
Save\t\t\t\t: "Αποθήκευση",\r\n
NewPage\t\t\t\t: "Νέα Σελίδα",\r\n
Preview\t\t\t\t: "Προεπισκόπιση",\r\n
Cut\t\t\t\t\t: "Αποκοπή",\r\n
Copy\t\t\t\t: "Αντιγραφή",\r\n
Paste\t\t\t\t: "Επικόλληση",\r\n
PasteText\t\t\t: "Επικόλληση (απλό κείμενο)",\r\n
PasteWord\t\t\t: "Επικόλληση από το Word",\r\n
Print\t\t\t\t: "Εκτύπωση",\r\n
SelectAll\t\t\t: "Επιλογή όλων",\r\n
RemoveFormat\t\t: "Αφαίρεση Μορφοποίησης",\r\n
InsertLinkLbl\t\t: "Σύνδεσμος (Link)",\r\n
InsertLink\t\t\t: "Εισαγωγή/Μεταβολή Συνδέσμου (Link)",\r\n
RemoveLink\t\t\t: "Αφαίρεση Συνδέσμου (Link)",\r\n
VisitLink\t\t\t: "Open Link",\t//MISSING\r\n
Anchor\t\t\t\t: "Εισαγωγή/επεξεργασία Anchor",\r\n
AnchorDelete\t\t: "Remove Anchor",\t//MISSING\r\n
InsertImageLbl\t\t: "Εικόνα",\r\n
InsertImage\t\t\t: "Εισαγωγή/Μεταβολή Εικόνας",\r\n
InsertFlashLbl\t\t: "Εισαγωγή Flash",\r\n
InsertFlash\t\t\t: "Εισαγωγή/επεξεργασία Flash",\r\n
InsertTableLbl\t\t: "Πίνακας",\r\n
InsertTable\t\t\t: "Εισαγωγή/Μεταβολή Πίνακα",\r\n
InsertLineLbl\t\t: "Γραμμή",\r\n
InsertLine\t\t\t: "Εισαγωγή Οριζόντιας Γραμμής",\r\n
InsertSpecialCharLbl: "Ειδικό Σύμβολο",\r\n
InsertSpecialChar\t: "Εισαγωγή Ειδικού Συμβόλου",\r\n
InsertSmileyLbl\t\t: "Smiley",\r\n
InsertSmiley\t\t: "Εισαγωγή Smiley",\r\n
About\t\t\t\t: "Περί του FCKeditor",\r\n
Bold\t\t\t\t: "Έντονα",\r\n
Italic\t\t\t\t: "Πλάγια",\r\n
Underline\t\t\t: "Υπογράμμιση",\r\n
StrikeThrough\t\t: "Διαγράμμιση",\r\n
Subscript\t\t\t: "Δείκτης",\r\n
Superscript\t\t\t: "Εκθέτης",\r\n
LeftJustify\t\t\t: "Στοίχιση Αριστερά",\r\n
CenterJustify\t\t: "Στοίχιση στο Κέντρο",\r\n
RightJustify\t\t: "Στοίχιση Δεξιά",\r\n
BlockJustify\t\t: "Πλήρης Στοίχιση (Block)",\r\n
DecreaseIndent\t\t: "Μείωση Εσοχής",\r\n
IncreaseIndent\t\t: "Αύξηση Εσοχής",\r\n
Blockquote\t\t\t: "Blockquote",\t//MISSING\r\n
CreateDiv\t\t\t: "Create Div Container",\t//MISSING\r\n
EditDiv\t\t\t\t: "Edit Div Container",\t//MISSING\r\n
DeleteDiv\t\t\t: "Remove Div Container",\t//MISSING\r\n
Undo\t\t\t\t: "Αναίρεση",\r\n
Redo\t\t\t\t: "Επαναφορά",\r\n
NumberedListLbl\t\t: "Λίστα με Αριθμούς",\r\n
NumberedList\t\t: "Εισαγωγή/Διαγραφή Λίστας με Αριθμούς",\r\n
BulletedListLbl\t\t: "Λίστα με Bullets",\r\n
BulletedList\t\t: "Εισαγωγή/Διαγραφή Λίστας με Bullets",\r\n
ShowTableBorders\t: "Προβολή Ορίων Πίνακα",\r\n
ShowDetails\t\t\t: "Προβολή Λεπτομερειών",\r\n
Style\t\t\t\t: "Στυλ",\r\n
FontFormat\t\t\t: "Μορφή Γραμματοσειράς",\r\n
Font\t\t\t\t: "Γραμματοσειρά",\r\n
FontSize\t\t\t: "Μέγεθος",\r\n
TextColor\t\t\t: "Χρώμα Γραμμάτων",\r\n
BGColor\t\t\t\t: "Χρώμα Υποβάθρου",\r\n
Source\t\t\t\t: "HTML κώδικας",\r\n
Find\t\t\t\t: "Αναζήτηση",\r\n
Replace\t\t\t\t: "Αντικατάσταση",\r\n
SpellCheck\t\t\t: "Ορθογραφικός έλεγχος",\r\n
UniversalKeyboard\t: "Διεθνής πληκτρολόγιο",\r\n
PageBreakLbl\t\t: "Τέλος σελίδας",\r\n
PageBreak\t\t\t: "Εισαγωγή τέλους σελίδας",\r\n
\r\n
Form\t\t\t: "Φόρμα",\r\n
Checkbox\t\t: "Κουτί επιλογής",\r\n
RadioButton\t\t: "Κουμπί Radio",\r\n
TextField\t\t: "Πεδίο κειμένου",\r\n
Textarea\t\t: "Περιοχή κειμένου",\r\n
HiddenField\t\t: "Κρυφό πεδίο",\r\n
Button\t\t\t: "Κουμπί",\r\n
SelectionField\t: "Πεδίο επιλογής",\r\n
ImageButton\t\t: "Κουμπί εικόνας",\r\n
\r\n
FitWindow\t\t: "Μεγιστοποίηση προγράμματος",\r\n
ShowBlocks\t\t: "Show Blocks",\t//MISSING\r\n
\r\n
// Context Menu\r\n
EditLink\t\t\t: "Μεταβολή Συνδέσμου (Link)",\r\n
CellCM\t\t\t\t: "Κελί",\r\n
RowCM\t\t\t\t: "Σειρά",\r\n
ColumnCM\t\t\t: "Στήλη",\r\n
InsertRowAfter\t\t: "Insert Row After",\t//MISSING\r\n
InsertRowBefore\t\t: "Insert Row Before",\t//MISSING\r\n
DeleteRows\t\t\t: "Διαγραφή Γραμμών",\r\n
InsertColumnAfter\t: "Insert Column After",\t//MISSING\r\n
InsertColumnBefore\t: "Insert Column Before",\t//MISSING\r\n
DeleteColumns\t\t: "Διαγραφή Κολωνών",\r\n
InsertCellAfter\t\t: "Insert Cell After",\t//MISSING\r\n
InsertCellBefore\t: "Insert Cell Before",\t//MISSING\r\n
DeleteCells\t\t\t: "Διαγραφή Κελιών",\r\n
MergeCells\t\t\t: "Ενοποίηση Κελιών",\r\n
MergeRight\t\t\t: "Merge Right",\t//MISSING\r\n
MergeDown\t\t\t: "Merge Down",\t//MISSING\r\n
HorizontalSplitCell\t: "Split Cell Horizontally",\t//MISSING\r\n
VerticalSplitCell\t: "Split Cell Vertically",\t//MISSING\r\n
TableDelete\t\t\t: "Διαγραφή πίνακα",\r\n
CellProperties\t\t: "Ιδιότητες Κελιού",\r\n
TableProperties\t\t: "Ιδιότητες Πίνακα",\r\n
ImageProperties\t\t: "Ιδιότητες Εικόνας",\r\n
FlashProperties\t\t: "Ιδιότητες Flash",\r\n
\r\n
AnchorProp\t\t\t: "Ιδιότητες άγκυρας",\r\n
ButtonProp\t\t\t: "Ιδιότητες κουμπιού",\r\n
CheckboxProp\t\t: "Ιδιότητες κουμπιού επιλογής",\r\n
HiddenFieldProp\t\t: "Ιδιότητες κρυφού πεδίου",\r\n
RadioButtonProp\t\t: "Ιδιότητες κουμπιού radio",\r\n
ImageButtonProp\t\t: "Ιδιότητες κουμπιού εικόνας",\r\n
TextFieldProp\t\t: "Ιδιότητες πεδίου κειμένου",\r\n
SelectionFieldProp\t: "Ιδιότητες πεδίου επιλογής",\r\n
TextareaProp\t\t: "Ιδιότητες περιοχής κειμένου",\r\n
FormProp\t\t\t: "Ιδιότητες φόρμας",\r\n
\r\n
FontFormats\t\t\t: "Κανονικό;Μορφοποιημένο;Διεύθυνση;Επικεφαλίδα 1;Επικεφαλίδα 2;Επικεφαλίδα 3;Επικεφαλίδα 4;Επικεφαλίδα 5;Επικεφαλίδα 6",\r\n
\r\n
// Alerts and Messages\r\n
ProcessingXHTML\t\t: "Επεξεργασία XHTML. Παρακαλώ περιμένετε...",\r\n
Done\t\t\t\t: "Έτοιμο",\r\n
PasteWordConfirm\t: "Το κείμενο που θέλετε να επικολήσετε, φαίνεται πως προέρχεται από το Word. Θέλετε να καθαριστεί πριν επικοληθεί;",\r\n
NotCompatiblePaste\t: "Αυτή η επιλογή είναι διαθέσιμη στον Internet Explorer έκδοση 5.5+. Θέλετε να γίνει η επικόλληση χωρίς καθαρισμό;",\r\n
UnknownToolbarItem\t: "Άγνωστο αντικείμενο της μπάρας εργαλείων \\"%1\\"",\r\n
UnknownCommand\t\t: "Άγνωστή εντολή \\"%1\\"",\r\n
NotImplemented\t\t: "Η εντολή δεν έχει ενεργοποιηθεί",\r\n
UnknownToolbarSet\t: "Η μπάρα εργαλείων \\"%1\\" δεν υπάρχει",\r\n
NoActiveX\t\t\t: "Οι ρυθμίσεις ασφαλείας του browser σας μπορεί να περιορίσουν κάποιες ρυθμίσεις του προγράμματος. Χρειάζεται να ενεργοποιήσετε την επιλογή \\"Run ActiveX controls and plug-ins\\". Ίσως παρουσιαστούν λάθη και παρατηρήσετε ελειπείς λειτουργίες.",\r\n
BrowseServerBlocked : "Οι πόροι του browser σας δεν είναι προσπελάσιμοι. Σιγουρευτείτε ότι δεν υπάρχουν ενεργοί popup blockers.",\r\n
DialogBlocked\t\t: "Δεν ήταν δυνατό να ανοίξει το παράθυρο διαλόγου. Σιγουρευτείτε ότι δεν υπάρχουν ενεργοί popup blockers.",\r\n
VisitLinkBlocked\t: "It was not possible to open a new window. Make sure all popup blockers are disabled.",\t//MISSING\r\n
\r\n
// Dialogs\r\n
DlgBtnOK\t\t\t: "OK",\r\n
DlgBtnCancel\t\t: "Ακύρωση",\r\n
DlgBtnClose\t\t\t: "Κλείσιμο",\r\n
DlgBtnBrowseServer\t: "Εξερεύνηση διακομιστή",\r\n
DlgAdvancedTag\t\t: "Για προχωρημένους",\r\n
DlgOpOther\t\t\t: "<Άλλα>",\r\n
DlgInfoTab\t\t\t: "Πληροφορίες",\r\n
DlgAlertUrl\t\t\t: "Παρακαλώ εισάγετε URL",\r\n
\r\n
// General Dialogs Labels\r\n
DlgGenNotSet\t\t: "<χωρίς>",\r\n
DlgGenId\t\t\t: "Id",\r\n
DlgGenLangDir\t\t: "Κατεύθυνση κειμένου",\r\n
DlgGenLangDirLtr\t: "Αριστερά προς Δεξιά (LTR)",\r\n
DlgGenLangDirRtl\t: "Δεξιά προς Αριστερά (RTL)",\r\n
DlgGenLangCode\t\t: "Κωδικός Γλώσσας",\r\n
DlgGenAccessKey\t\t: "Συντόμευση (Access Key)",\r\n
DlgGenName\t\t\t: "Όνομα",\r\n
DlgGenTabIndex\t\t: "Tab Index",\r\n
DlgGenLongDescr\t\t: "Αναλυτική περιγραφή URL",\r\n
DlgGenClass\t\t\t: "Stylesheet Classes",\r\n
DlgGenTitle\t\t\t: "Συμβουλευτικός τίτλος",\r\n
DlgGenContType\t\t: "Συμβουλευτικός τίτλος περιεχομένου",\r\n
DlgGenLinkCharset\t: "Linked Resource Charset",\r\n
DlgGenStyle\t\t\t: "Στύλ",\r\n
\r\n
// Image Dialog\r\n
DlgImgTitle\t\t\t: "Ιδιότητες Εικόνας",\r\n
DlgImgInfoTab\t\t: "Πληροφορίες Εικόνας",\r\n
DlgImgBtnUpload\t\t: "Αποστολή στον Διακομιστή",\r\n
DlgImgURL\t\t\t: "URL",\r\n
DlgImgUpload\t\t: "Αποστολή",\r\n
DlgImgAlt\t\t\t: "Εναλλακτικό Κείμενο (ALT)",\r\n
DlgImgWidth\t\t\t: "Πλάτος",\r\n
DlgImgHeight\t\t: "Ύψος",\r\n
DlgImgLockRatio\t\t: "Κλείδωμα Αναλογίας",\r\n
DlgBtnResetSize\t\t: "Επαναφορά Αρχικού Μεγέθους",\r\n
DlgImgBorder\t\t: "Περιθώριο",\r\n
DlgImgHSpace\t\t: "Οριζόντιος Χώρος (HSpace)",\r\n
DlgImgVSpace\t\t: "Κάθετος Χώρος (VSpace)",\r\n
DlgImgAlign\t\t\t: "Ευθυγράμμιση (Align)",\r\n
DlgImgAlignLeft\t\t: "Αριστερά",\r\n
DlgImgAlignAbsBottom: "Απόλυτα Κάτω (Abs Bottom)",\r\n
DlgImgAlignAbsMiddle: "Απόλυτα στη Μέση (Abs Middle)",\r\n
DlgImgAlignBaseline\t: "Γραμμή Βάσης (Baseline)",\r\n
DlgImgAlignBottom\t: "Κάτω (Bottom)",\r\n
DlgImgAlignMiddle\t: "Μέση (Middle)",\r\n
DlgImgAlignRight\t: "Δεξιά (Right)",\r\n
DlgImgAlignTextTop\t: "Κορυφή Κειμένου (Text Top)",\r\n
DlgImgAlignTop\t\t: "Πάνω (Top)",\r\n
DlgImgPreview\t\t: "Προεπισκόπιση",\r\n
DlgImgAlertUrl\t\t: "Εισάγετε την τοποθεσία (URL) της εικόνας",\r\n
DlgImgLinkTab\t\t: "Σύνδεσμος",\r\n
\r\n
// Flash Dialog\r\n
DlgFlashTitle\t\t: "Ιδιότητες flash",\r\n
DlgFlashChkPlay\t\t: "Αυτόματη έναρξη",\r\n
DlgFlashChkLoop\t\t: "Επανάληψη",\r\n
DlgFlashChkMenu\t\t: "Ενεργοποίηση Flash Menu",\r\n
DlgFlashScale\t\t: "Κλίμακα",\r\n
DlgFlashScaleAll\t: "Εμφάνιση όλων",\r\n
DlgFlashScaleNoBorder\t: "Χωρίς όρια",\r\n
DlgFlashScaleFit\t: "Ακριβής εφαρμογή",\r\n
\r\n
// Link Dialog\r\n
DlgLnkWindowTitle\t: "Σύνδεσμος (Link)",\r\n
DlgLnkInfoTab\t\t: "Link",\r\n
DlgLnkTargetTab\t\t: "Παράθυρο Στόχος (Target)",\r\n
\r\n
DlgLnkType\t\t\t: "Τύπος συνδέσμου (Link)",\r\n
DlgLnkTypeURL\t\t: "URL",\r\n
DlgLnkTypeAnchor\t: "Άγκυρα σε αυτή τη σελίδα",\r\n
DlgLnkTypeEMail\t\t: "E-Mail",\r\n
DlgLnkProto\t\t\t: "Προτόκολο",\r\n
DlgLnkProtoOther\t: "<άλλο>",\r\n
DlgLnkURL\t\t\t: "URL",\r\n
DlgLnkAnchorSel\t\t: "Επιλέξτε μια άγκυρα",\r\n
DlgLnkAnchorByName\t: "Βάσει του Ονόματος (Name) της άγκυρας",\r\n
DlgLnkAnchorById\t: "Βάσει του Element Id",\r\n
DlgLnkNoAnchors\t\t: "(Δεν υπάρχουν άγκυρες στο κείμενο)",\r\n
DlgLnkEMail\t\t\t: "Διεύθυνση Ηλεκτρονικού Ταχυδρομείου",\r\n
DlgLnkEMailSubject\t: "Θέμα Μηνύματος",\r\n
DlgLnkEMailBody\t\t: "Κείμενο Μηνύματος",\r\n
DlgLnkUpload\t\t: "Αποστολή",\r\n
DlgLnkBtnUpload\t\t: "Αποστολή στον Διακομιστή",\r\n
\r\n
DlgLnkTarget\t\t: "Παράθυρο Στόχος (Target)",\r\n
DlgLnkTargetFrame\t: "<πλαίσιο>",\r\n
DlgLnkTargetPopup\t: "<παράθυρο popup>",\r\n
DlgLnkTargetBlank\t: "Νέο Παράθυρο (_blank)",\r\n
DlgLnkTargetParent\t: "Γονικό Παράθυρο (_parent)",\r\n
DlgLnkTargetSelf\t: "Ίδιο Παράθυρο (_self)",\r\n
DlgLnkTargetTop\t\t: "Ανώτατο Παράθυρο (_top)",\r\n
DlgLnkTargetFrameName\t: "Όνομα πλαισίου στόχου",\r\n
DlgLnkPopWinName\t: "Όνομα Popup Window",\r\n
DlgLnkPopWinFeat\t: "Επιλογές Popup Window",\r\n
DlgLnkPopResize\t\t: "Με αλλαγή Μεγέθους",\r\n
DlgLnkPopLocation\t: "Μπάρα Τοποθεσίας",\r\n
DlgLnkPopMenu\t\t: "Μπάρα Menu",\r\n
DlgLnkPopScroll\t\t: "Μπάρες Κύλισης",\r\n
DlgLnkPopStatus\t\t: "Μπάρα Status",\r\n
DlgLnkPopToolbar\t: "Μπάρα Εργαλείων",\r\n
DlgLnkPopFullScrn\t: "Ολόκληρη η Οθόνη (IE)",\r\n
DlgLnkPopDependent\t: "Dependent (Netscape)",\r\n
DlgLnkPopWidth\t\t: "Πλάτος",\r\n
DlgLnkPopHeight\t\t: "Ύψος",\r\n
DlgLnkPopLeft\t\t: "Τοποθεσία Αριστερής Άκρης",\r\n
DlgLnkPopTop\t\t: "Τοποθεσία Πάνω Άκρης",\r\n
\r\n
DlnLnkMsgNoUrl\t\t: "Εισάγετε την τοποθεσία (URL) του υπερσυνδέσμου (Link)",\r\n
DlnLnkMsgNoEMail\t: "Εισάγετε την διεύθυνση ηλεκτρονικού ταχυδρομείου",\r\n
DlnLnkMsgNoAnchor\t: "Επιλέξτε ένα Anchor",\r\n
DlnLnkMsgInvPopName\t: "Το όνομα του popup πρέπει να αρχίζει με χαρακτήρα της αλφαβήτου και να μην περιέχει κενά",\r\n
\r\n
// Color Dialog\r\n
DlgColorTitle\t\t: "Επιλογή χρώματος",\r\n
DlgColorBtnClear\t: "Καθαρισμός",\r\n
DlgColorHighlight\t: "Προεπισκόπιση",\r\n
DlgColorSelected\t: "Επιλεγμένο",\r\n
\r\n
// Smiley Dialog\r\n
DlgSmileyTitle\t\t: "Επιλέξτε ένα Smiley",\r\n
\r\n
// Special Character Dialog\r\n
DlgSpecialCharTitle\t: "Επιλέξτε ένα Ειδικό Σύμβολο",\r\n
\r\n
// Table Dialog\r\n
DlgTableTitle\t\t: "Ιδιότητες Πίνακα",\r\n
DlgTableRows\t\t: "Γραμμές",\r\n
DlgTableColumns\t\t: "Κολώνες",\r\n
DlgTableBorder\t\t: "Μέγεθος Περιθωρίου",\r\n
DlgTableAlign\t\t: "Στοίχιση",\r\n
DlgTableAlignNotSet\t: "<χωρίς>",\r\n
DlgTableAlignLeft\t: "Αριστερά",\r\n
DlgTableAlignCenter\t: "Κέντρο",\r\n
DlgTableAlignRight\t: "Δεξιά",\r\n
DlgTableWidth\t\t: "Πλάτος",\r\n
DlgTableWidthPx\t\t: "pixels",\r\n
DlgTableWidthPc\t\t: "\\%",\r\n
DlgTableHeight\t\t: "Ύψος",\r\n
DlgTableCellSpace\t: "Απόσταση κελιών",\r\n
DlgTableCellPad\t\t: "Γέμισμα κελιών",\r\n
DlgTableCaption\t\t: "Υπέρτιτλος",\r\n
DlgTableSummary\t\t: "Περίληψη",\r\n
DlgTableHeaders\t\t: "Headers",\t//MISSING\r\n
DlgTableHeadersNone\t\t: "None",\t//MISSING\r\n
DlgTableHeadersColumn\t: "First column",\t//MISSING\r\n
DlgTableHeadersRow\t\t: "First Row",\t//MISSING\r\n
DlgTableHeadersBoth\t\t: "Both",\t//MISSING\r\n
\r\n
// Table Cell Dialog\r\n
DlgCellTitle\t\t: "Ιδιότητες Κελιού",\r\n
DlgCellWidth\t\t: "Πλάτος",\r\n
DlgCellWidthPx\t\t: "pixels",\r\n
DlgCellWidthPc\t\t: "\\%",\r\n
DlgCellHeight\t\t: "Ύψος",\r\n
DlgCellWordWrap\t\t: "Με αλλαγή γραμμής",\r\n
DlgCellWordWrapNotSet\t: "<χωρίς>",\r\n
DlgCellWordWrapYes\t: "Ναι",\r\n
DlgCellWordWrapNo\t: "Όχι",\r\n
DlgCellHorAlign\t\t: "Οριζόντια Στοίχιση",\r\n
DlgCellHorAlignNotSet\t: "<χωρίς>",\r\n
DlgCellHorAlignLeft\t: "Αριστερά",\r\n
DlgCellHorAlignCenter\t: "Κέντρο",\r\n
DlgCellHorAlignRight: "Δεξιά",\r\n
DlgCellVerAlign\t\t: "Κάθετη Στοίχιση",\r\n
DlgCellVerAlignNotSet\t: "<χωρίς>",\r\n
DlgCellVerAlignTop\t: "Πάνω (Top)",\r\n
DlgCellVerAlignMiddle\t: "Μέση (Middle)",\r\n
DlgCellVerAlignBottom\t: "Κάτω (Bottom)",\r\n
DlgCellVerAlignBaseline\t: "Γραμμή Βάσης (Baseline)",\r\n
DlgCellType\t\t: "Cell Type",\t//MISSING\r\n
DlgCellTypeData\t\t: "Data",\t//MISSING\r\n
DlgCellTypeHeader\t: "Header",\t//MISSING\r\n
DlgCellRowSpan\t\t: "Αριθμός Γραμμών (Rows Span)",\r\n
DlgCellCollSpan\t\t: "Αριθμός Κολωνών (Columns Span)",\r\n
DlgCellBackColor\t: "Χρώμα Υποβάθρου",\r\n
DlgCellBorderColor\t: "Χρώμα Περιθωρίου",\r\n
DlgCellBtnSelect\t: "Επιλογή...",\r\n
\r\n
// Find and Replace Dialog\r\n
DlgFindAndReplaceTitle\t: "Find and Replace",\t//MISSING\r\n
\r\n
// Find Dialog\r\n
DlgFindTitle\t\t: "Αναζήτηση",\r\n
DlgFindFindBtn\t\t: "Αναζήτηση",\r\n
DlgFindNotFoundMsg\t: "Το κείμενο δεν βρέθηκε.",\r\n
\r\n
// Replace Dialog\r\n
DlgReplaceTitle\t\t\t: "Αντικατάσταση",\r\n
DlgReplaceFindLbl\t\t: "Αναζήτηση:",\r\n
DlgReplaceReplaceLbl\t: "Αντικατάσταση με:",\r\n
DlgReplaceCaseChk\t\t: "Έλεγχος πεζών/κεφαλαίων",\r\n
DlgReplaceReplaceBtn\t: "Αντικατάσταση",\r\n
DlgReplaceReplAllBtn\t: "Αντικατάσταση Όλων",\r\n
DlgReplaceWordChk\t\t: "Εύρεση πλήρους λέξης",\r\n
\r\n
// Paste Operations / Dialog\r\n
PasteErrorCut\t: "Οι ρυθμίσεις ασφαλείας του φυλλομετρητή σας δεν επιτρέπουν την επιλεγμένη εργασία αποκοπής. Χρησιμοποιείστε το πληκτρολόγιο (Ctrl+X).",\r\n
PasteErrorCopy\t: "Οι ρυθμίσεις ασφαλείας του φυλλομετρητή σας δεν επιτρέπουν την επιλεγμένη εργασία αντιγραφής. Χρησιμοποιείστε το πληκτρολόγιο (Ctrl+C).",\r\n
\r\n
PasteAsText\t\t: "Επικόλληση ως Απλό Κείμενο",\r\n
PasteFromWord\t: "Επικόλληση από το Word",\r\n
\r\n
DlgPasteMsg2\t: "Παρακαλώ επικολήστε στο ακόλουθο κουτί χρησιμοποιόντας το πληκτρολόγιο (<STRONG>Ctrl+V</STRONG>) και πατήστε <STRONG>OK</STRONG>.",\r\n
DlgPasteSec\t\t: "Because of your browser security settings, the editor is not able to access your clipboard data directly. You are required to paste it again in this window.",\t//MISSING\r\n
DlgPasteIgnoreFont\t\t: "Αγνόηση προδιαγραφών γραμματοσειράς",\r\n
DlgPasteRemoveStyles\t: "Αφαίρεση προδιαγραφών στύλ",\r\n
\r\n
// Color Picker\r\n
ColorAutomatic\t: "Αυτόματο",\r\n
ColorMoreColors\t: "Περισσότερα χρώματα...",\r\n
\r\n
// Document Properties\r\n
DocProps\t\t: "Ιδιότητες εγγράφου",\r\n
\r\n
// Anchor Dialog\r\n
DlgAnchorTitle\t\t: "Ιδιότητες άγκυρας",\r\n
DlgAnchorName\t\t: "Όνομα άγκυρας",\r\n
DlgAnchorErrorName\t: "Παρακαλούμε εισάγετε όνομα άγκυρας",\r\n
\r\n
// Speller Pages Dialog\r\n
DlgSpellNotInDic\t\t: "Δεν υπάρχει στο λεξικό",\r\n
DlgSpellChangeTo\t\t: "Αλλαγή σε",\r\n
DlgSpellBtnIgnore\t\t: "Αγνόηση",\r\n
DlgSpellBtnIgnoreAll\t: "Αγνόηση όλων",\r\n
DlgSpellBtnReplace\t\t: "Αντικατάσταση",\r\n
DlgSpellBtnReplaceAll\t: "Αντικατάσταση όλων",\r\n
DlgSpellBtnUndo\t\t\t: "Αναίρεση",\r\n
DlgSpellNoSuggestions\t: "- Δεν υπάρχουν προτάσεις -",\r\n
DlgSpellProgress\t\t: "Ορθογραφικός έλεγχος σε εξέλιξη...",\r\n
DlgSpellNoMispell\t\t: "Ο ορθογραφικός έλεγχος ολοκληρώθηκε: Δεν βρέθηκαν λάθη",\r\n
DlgSpellNoChanges\t\t: "Ο ορθογραφικός έλεγχος ολοκληρώθηκε: Δεν άλλαξαν λέξεις",\r\n
DlgSpellOneChange\t\t: "Ο ορθογραφικός έλεγχος ολοκληρώθηκε: Μια λέξη άλλαξε",\r\n
DlgSpellManyChanges\t\t: "Ο ορθογραφικός έλεγχος ολοκληρώθηκε: %1 λέξεις άλλαξαν",\r\n
\r\n
IeSpellDownload\t\t\t: "Δεν υπάρχει εγκατεστημένος ορθογράφος. Θέλετε να τον κατεβάσετε τώρα;",\r\n
\r\n
// Button Dialog\r\n
DlgButtonText\t\t: "Κείμενο (Τιμή)",\r\n
DlgButtonType\t\t: "Τύπος",\r\n
DlgButtonTypeBtn\t: "Κουμπί",\r\n
DlgButtonTypeSbm\t: "Καταχώρηση",\r\n
DlgButtonTypeRst\t: "Επαναφορά",\r\n
\r\n
// Checkbox and Radio Button Dialogs\r\n
DlgCheckboxName\t\t: "Όνομα",\r\n
DlgCheckboxValue\t: "Τιμή",\r\n
DlgCheckboxSelected\t: "Επιλεγμένο",\r\n
\r\n
// Form Dialog\r\n
DlgFormName\t\t: "Όνομα",\r\n
DlgFormAction\t: "Δράση",\r\n
DlgFormMethod\t: "Μάθοδος",\r\n
\r\n
// Select Field Dialog\r\n
DlgSelectName\t\t: "Όνομα",\r\n
DlgSelectValue\t\t: "Τιμή",\r\n
DlgSelectSize\t\t: "Μέγεθος",\r\n
DlgSelectLines\t\t: "γραμμές",\r\n
DlgSelectChkMulti\t: "Πολλαπλές επιλογές",\r\n
DlgSelectOpAvail\t: "Διαθέσιμες επιλογές",\r\n
DlgSelectOpText\t\t: "Κείμενο",\r\n
DlgSelectOpValue\t: "Τιμή",\r\n
DlgSelectBtnAdd\t\t: "Προσθήκη",\r\n
DlgSelectBtnModify\t: "Αλλαγή",\r\n
DlgSelectBtnUp\t\t: "Πάνω",\r\n
DlgSelectBtnDown\t: "Κάτω",\r\n
DlgSelectBtnSetValue : "Προεπιλεγμένη επιλογή",\r\n
DlgSelectBtnDelete\t: "Διαγραφή",\r\n
\r\n
// Textarea Dialog\r\n
DlgTextareaName\t: "Όνομα",\r\n
DlgTextareaCols\t: "Στήλες",\r\n
DlgTextareaRows\t: "Σειρές",\r\n
\r\n
// Text Field Dialog\r\n
DlgTextName\t\t\t: "Όνομα",\r\n
DlgTextValue\t\t: "Τιμή",\r\n
DlgTextCharWidth\t: "Μήκος χαρακτήρων",\r\n
DlgTextMaxChars\t\t: "Μέγιστοι χαρακτήρες",\r\n
DlgTextType\t\t\t: "Τύπος",\r\n
DlgTextTypeText\t\t: "Κείμενο",\r\n
DlgTextTypePass\t\t: "Κωδικός",\r\n
\r\n
// Hidden Field Dialog\r\n
DlgHiddenName\t: "Όνομα",\r\n
DlgHiddenValue\t: "Τιμή",\r\n
\r\n
// Bulleted List Dialog\r\n
BulletedListProp\t: "Ιδιότητες λίστας Bulleted",\r\n
NumberedListProp\t: "Ιδιότητες αριθμημένης λίστας ",\r\n
DlgLstStart\t\t\t: "Αρχή",\r\n
DlgLstType\t\t\t: "Τύπος",\r\n
DlgLstTypeCircle\t: "Κύκλος",\r\n
DlgLstTypeDisc\t\t: "Δίσκος",\r\n
DlgLstTypeSquare\t: "Τετράγωνο",\r\n
DlgLstTypeNumbers\t: "Αριθμοί (1, 2, 3)",\r\n
DlgLstTypeLCase\t\t: "Πεζά γράμματα (a, b, c)",\r\n
DlgLstTypeUCase\t\t: "Κεφαλαία γράμματα (A, B, C)",\r\n
DlgLstTypeSRoman\t: "Μικρά λατινικά αριθμητικά (i, ii, iii)",\r\n
DlgLstTypeLRoman\t: "Μεγάλα λατινικά αριθμητικά (I, II, III)",\r\n
\r\n
// Document Properties Dialog\r\n
DlgDocGeneralTab\t: "Γενικά",\r\n
DlgDocBackTab\t\t: "Φόντο",\r\n
DlgDocColorsTab\t\t: "Χρώματα και περιθώρια",\r\n
DlgDocMetaTab\t\t: "Δεδομένα Meta",\r\n
\r\n
DlgDocPageTitle\t\t: "Τίτλος σελίδας",\r\n
DlgDocLangDir\t\t: "Κατεύθυνση γραφής",\r\n
DlgDocLangDirLTR\t: "αριστερά προς δεξιά (LTR)",\r\n
DlgDocLangDirRTL\t: "δεξιά προς αριστερά (RTL)",\r\n
DlgDocLangCode\t\t: "Κωδικός γλώσσας",\r\n
DlgDocCharSet\t\t: "Κωδικοποίηση χαρακτήρων",\r\n
DlgDocCharSetCE\t\t: "Κεντρικής Ευρώπης",\r\n
DlgDocCharSetCT\t\t: "Παραδοσιακά κινέζικα (Big5)",\r\n
DlgDocCharSetCR\t\t: "Κυριλλική",\r\n
DlgDocCharSetGR\t\t: "Ελληνική",\r\n
DlgDocCharSetJP\t\t: "Ιαπωνική",\r\n
DlgDocCharSetKR\t\t: "Κορεάτικη",\r\n
DlgDocCharSetTR\t\t: "Τουρκική",\r\n
DlgDocCharSetUN\t\t: "Διεθνής (UTF-8)",\r\n
DlgDocCharSetWE\t\t: "Δυτικής Ευρώπης",\r\n
DlgDocCharSetOther\t: "Άλλη κωδικοποίηση χαρακτήρων",\r\n
\r\n
DlgDocDocType\t\t: "Επικεφαλίδα τύπου εγγράφου",\r\n
DlgDocDocTypeOther\t: "Άλλη επικεφαλίδα τύπου εγγράφου",\r\n
DlgDocIncXHTML\t\t: "Να συμπεριληφθούν οι δηλώσεις XHTML",\r\n
DlgDocBgColor\t\t: "Χρώμα φόντου",\r\n
DlgDocBgImage\t\t: "Διεύθυνση εικόνας φόντου",\r\n
DlgDocBgNoScroll\t: "Φόντο χωρίς κύλιση",\r\n
DlgDocCText\t\t\t: "Κείμενο",\r\n
DlgDocCLink\t\t\t: "Σύνδεσμος",\r\n
DlgDocCVisited\t\t: "Σύνδεσμος που έχει επισκευθεί",\r\n
DlgDocCActive\t\t: "Ενεργός σύνδεσμος",\r\n
DlgDocMargins\t\t: "Περιθώρια σελίδας",\r\n
DlgDocMaTop\t\t\t: "Κορυφή",\r\n
DlgDocMaLeft\t\t: "Αριστερά",\r\n
DlgDocMaRight\t\t: "Δεξιά",\r\n
DlgDocMaBottom\t\t: "Κάτω",\r\n
DlgDocMeIndex\t\t: "Λέξεις κλειδιά δείκτες εγγράφου (διαχωρισμός με κόμμα)",\r\n
DlgDocMeDescr\t\t: "Περιγραφή εγγράφου",\r\n
DlgDocMeAuthor\t\t: "Συγγραφέας",\r\n
DlgDocMeCopy\t\t: "Πνευματικά δικαιώματα",\r\n
DlgDocPreview\t\t: "Προεπισκόπηση",\r\n
\r\n
// Templates Dialog\r\n
Templates\t\t\t: "Πρότυπα",\r\n
DlgTemplatesTitle\t: "Πρότυπα περιεχομένου",\r\n
DlgTemplatesSelMsg\t: "Παρακαλώ επιλέξτε πρότυπο για εισαγωγή στο πρόγραμμα<br>(τα υπάρχοντα περιεχόμενα θα χαθούν):",\r\n
DlgTemplatesLoading\t: "Φόρτωση καταλόγου προτύπων. Παρακαλώ περιμένετε...",\r\n
DlgTemplatesNoTpl\t: "(Δεν έχουν καθοριστεί πρότυπα)",\r\n
DlgTemplatesReplace\t: "Αντικατάσταση υπάρχοντων περιεχομένων",\r\n
\r\n
// About Dialog\r\n
DlgAboutAboutTab\t: "Σχετικά",\r\n
DlgAboutBrowserInfoTab\t: "Πληροφορίες Browser",\r\n
DlgAboutLicenseTab\t: "Άδεια",\r\n
DlgAboutVersion\t\t: "έκδοση",\r\n
DlgAboutInfo\t\t: "Για περισσότερες πληροφορίες",\r\n
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
            <value> <int>26011</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
