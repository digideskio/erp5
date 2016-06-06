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
            <value> <string>ts83858910.01</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>fck_image.js</string> </value>
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
 * Scripts related to the Image dialog window (see fck_image.html).\r\n
 */\r\n
\r\n
var dialog\t\t= window.parent ;\r\n
var oEditor\t\t= dialog.InnerDialogLoaded() ;\r\n
var FCK\t\t\t= oEditor.FCK ;\r\n
var FCKLang\t\t= oEditor.FCKLang ;\r\n
var FCKConfig\t= oEditor.FCKConfig ;\r\n
var FCKDebug\t= oEditor.FCKDebug ;\r\n
var FCKTools\t= oEditor.FCKTools ;\r\n
\r\n
var bImageButton = ( document.location.search.length > 0 && document.location.search.substr(1) == \'ImageButton\' ) ;\r\n
\r\n
//#### Dialog Tabs\r\n
\r\n
// Set the dialog tabs.\r\n
dialog.AddTab( \'Info\', FCKLang.DlgImgInfoTab ) ;\r\n
\r\n
if ( !bImageButton && !FCKConfig.ImageDlgHideLink )\r\n
\tdialog.AddTab( \'Link\', FCKLang.DlgImgLinkTab ) ;\r\n
\r\n
if ( FCKConfig.ImageUpload )\r\n
\tdialog.AddTab( \'Upload\', FCKLang.DlgLnkUpload ) ;\r\n
\r\n
if ( !FCKConfig.ImageDlgHideAdvanced )\r\n
\tdialog.AddTab( \'Advanced\', FCKLang.DlgAdvancedTag ) ;\r\n
\r\n
// Function called when a dialog tag is selected.\r\n
function OnDialogTabChange( tabCode )\r\n
{\r\n
\tShowE(\'divInfo\'\t\t, ( tabCode == \'Info\' ) ) ;\r\n
\tShowE(\'divLink\'\t\t, ( tabCode == \'Link\' ) ) ;\r\n
\tShowE(\'divUpload\'\t, ( tabCode == \'Upload\' ) ) ;\r\n
\tShowE(\'divAdvanced\'\t, ( tabCode == \'Advanced\' ) ) ;\r\n
}\r\n
\r\n
// Get the selected image (if available).\r\n
var oImage = dialog.Selection.GetSelectedElement() ;\r\n
\r\n
if ( oImage && oImage.tagName != \'IMG\' && !( oImage.tagName == \'INPUT\' && oImage.type == \'image\' ) )\r\n
\toImage = null ;\r\n
\r\n
// Get the active link.\r\n
var oLink = dialog.Selection.GetSelection().MoveToAncestorNode( \'A\' ) ;\r\n
\r\n
var oImageOriginal ;\r\n
\r\n
function UpdateOriginal( resetSize )\r\n
{\r\n
\tif ( !eImgPreview )\r\n
\t\treturn ;\r\n
\r\n
\tif ( GetE(\'txtUrl\').value.length == 0 )\r\n
\t{\r\n
\t\toImageOriginal = null ;\r\n
\t\treturn ;\r\n
\t}\r\n
\r\n
\toImageOriginal = document.createElement( \'IMG\' ) ;\t// new Image() ;\r\n
\r\n
\tif ( resetSize )\r\n
\t{\r\n
\t\toImageOriginal.onload = function()\r\n
\t\t{\r\n
\t\t\tthis.onload = null ;\r\n
\t\t\tResetSizes() ;\r\n
\t\t}\r\n
\t}\r\n
\r\n
\toImageOriginal.src = eImgPreview.src ;\r\n
}\r\n
\r\n
var bPreviewInitialized ;\r\n
\r\n
window.onload = function()\r\n
{\r\n
\t// Translate the dialog box texts.\r\n
\toEditor.FCKLanguageManager.TranslatePage(document) ;\r\n
\r\n
\tGetE(\'btnLockSizes\').title = FCKLang.DlgImgLockRatio ;\r\n
\tGetE(\'btnResetSize\').title = FCKLang.DlgBtnResetSize ;\r\n
\r\n
\t// Load the selected element information (if any).\r\n
\tLoadSelection() ;\r\n
\r\n
\t// Show/Hide the "Browse Server" button.\r\n
\tGetE(\'tdBrowse\').style.display\t\t\t\t= FCKConfig.ImageBrowser\t? \'\' : \'none\' ;\r\n
\tGetE(\'divLnkBrowseServer\').style.display\t= FCKConfig.LinkBrowser\t\t? \'\' : \'none\' ;\r\n
\r\n
\tUpdateOriginal() ;\r\n
\r\n
\t// Set the actual uploader URL.\r\n
\tif ( FCKConfig.ImageUpload )\r\n
\t\tGetE(\'frmUpload\').action = FCKConfig.ImageUploadURL ;\r\n
\r\n
\tdialog.SetAutoSize( true ) ;\r\n
\r\n
\t// Activate the "OK" button.\r\n
\tdialog.SetOkButton( true ) ;\r\n
\r\n
\tSelectField( \'txtUrl\' ) ;\r\n
}\r\n
\r\n
function LoadSelection()\r\n
{\r\n
\tif ( ! oImage ) return ;\r\n
\r\n
\tvar sUrl = oImage.getAttribute( \'_fcksavedurl\' ) ;\r\n
\tif ( sUrl == null )\r\n
\t\tsUrl = GetAttribute( oImage, \'src\', \'\' ) ;\r\n
\r\n
\tGetE(\'txtUrl\').value    = sUrl ;\r\n
\tGetE(\'txtAlt\').value    = GetAttribute( oImage, \'alt\', \'\' ) ;\r\n
\tGetE(\'txtVSpace\').value\t= GetAttribute( oImage, \'vspace\', \'\' ) ;\r\n
\tGetE(\'txtHSpace\').value\t= GetAttribute( oImage, \'hspace\', \'\' ) ;\r\n
\tGetE(\'txtBorder\').value\t= GetAttribute( oImage, \'border\', \'\' ) ;\r\n
\tGetE(\'cmbAlign\').value\t= GetAttribute( oImage, \'align\', \'\' ) ;\r\n
\r\n
\tvar iWidth, iHeight ;\r\n
\r\n
\tvar regexSize = /^\\s*(\\d+)px\\s*$/i ;\r\n
\r\n
\tif ( oImage.style.width )\r\n
\t{\r\n
\t\tvar aMatchW  = oImage.style.width.match( regexSize ) ;\r\n
\t\tif ( aMatchW )\r\n
\t\t{\r\n
\t\t\tiWidth = aMatchW[1] ;\r\n
\t\t\toImage.style.width = \'\' ;\r\n
\t\t\tSetAttribute( oImage, \'width\' , iWidth ) ;\r\n
\t\t}\r\n
\t}\r\n
\r\n
\tif ( oImage.style.height )\r\n
\t{\r\n
\t\tvar aMatchH  = oImage.style.height.match( regexSize ) ;\r\n
\t\tif ( aMatchH )\r\n
\t\t{\r\n
\t\t\tiHeight = aMatchH[1] ;\r\n
\t\t\toImage.style.height = \'\' ;\r\n
\t\t\tSetAttribute( oImage, \'height\', iHeight ) ;\r\n
\t\t}\r\n
\t}\r\n
\r\n
\tGetE(\'txtWidth\').value\t= iWidth ? iWidth : GetAttribute( oImage, "width", \'\' ) ;\r\n
\tGetE(\'txtHeight\').value\t= iHeight ? iHeight : GetAttribute( oImage, "height", \'\' ) ;\r\n
\r\n
\t// Get Advances Attributes\r\n
\tGetE(\'txtAttId\').value\t\t\t= oImage.id ;\r\n
\tGetE(\'cmbAttLangDir\').value\t\t= oImage.dir ;\r\n
\tGetE(\'txtAttLangCode\').value\t= oImage.lang ;\r\n
\tGetE(\'txtAttTitle\').value\t\t= oImage.title ;\r\n
\tGetE(\'txtLongDesc\').value\t\t= oImage.longDesc ;\r\n
\r\n
\tif ( oEditor.FCKBrowserInfo.IsIE )\r\n
\t{\r\n
\t\tGetE(\'txtAttClasses\').value = oImage.className || \'\' ;\r\n
\t\tGetE(\'txtAttStyle\').value = oImage.style.cssText ;\r\n
\t}\r\n
\telse\r\n
\t{\r\n
\t\tGetE(\'txtAttClasses\').value = oImage.getAttribute(\'class\',2) || \'\' ;\r\n
\t\tGetE(\'txtAttStyle\').value = oImage.getAttribute(\'style\',2) ;\r\n
\t}\r\n
\r\n
\tif ( oLink )\r\n
\t{\r\n
\t\tvar sLinkUrl = oLink.getAttribute( \'_fcksavedurl\' ) ;\r\n
\t\tif ( sLinkUrl == null )\r\n
\t\t\tsLinkUrl = oLink.getAttribute(\'href\',2) ;\r\n
\r\n
\t\tGetE(\'txtLnkUrl\').value\t\t= sLinkUrl ;\r\n
\t\tGetE(\'cmbLnkTarget\').value\t= oLink.target ;\r\n
\t}\r\n
\r\n
\tUpdatePreview() ;\r\n
}\r\n
\r\n
//#### The OK button was hit.\r\n
function Ok()\r\n
{\r\n
\tif ( GetE(\'txtUrl\').value.length == 0 )\r\n
\t{\r\n
\t\tdialog.SetSelectedTab( \'Info\' ) ;\r\n
\t\tGetE(\'txtUrl\').focus() ;\r\n
\r\n
\t\talert( FCKLang.DlgImgAlertUrl ) ;\r\n
\r\n
\t\treturn false ;\r\n
\t}\r\n
\r\n
\tvar bHasImage = ( oImage != null ) ;\r\n
\r\n
\tif ( bHasImage && bImageButton && oImage.tagName == \'IMG\' )\r\n
\t{\r\n
\t\tif ( confirm( \'Do you want to transform the selected image on a image button?\' ) )\r\n
\t\t\toImage = null ;\r\n
\t}\r\n
\telse if ( bHasImage && !bImageButton && oImage.tagName == \'INPUT\' )\r\n
\t{\r\n
\t\tif ( confirm( \'Do you want to transform the selected image button on a simple image?\' ) )\r\n
\t\t\toImage = null ;\r\n
\t}\r\n
\r\n
\toEditor.FCKUndo.SaveUndoStep() ;\r\n
\tif ( !bHasImage )\r\n
\t{\r\n
\t\tif ( bImageButton )\r\n
\t\t{\r\n
\t\t\toImage = FCK.EditorDocument.createElement( \'input\' ) ;\r\n
\t\t\toImage.type = \'image\' ;\r\n
\t\t\toImage = FCK.InsertElement( oImage ) ;\r\n
\t\t}\r\n
\t\telse\r\n
\t\t\toImage = FCK.InsertElement( \'img\' ) ;\r\n
\t}\r\n
\r\n
\tUpdateImage( oImage ) ;\r\n
\r\n
\tvar sLnkUrl = GetE(\'txtLnkUrl\').value.Trim() ;\r\n
\r\n
\tif ( sLnkUrl.length == 0 )\r\n
\t{\r\n
\t\tif ( oLink )\r\n
\t\t\tFCK.ExecuteNamedCommand( \'Unlink\' ) ;\r\n
\t}\r\n
\telse\r\n
\t{\r\n
\t\tif ( oLink )\t// Modifying an existent link.\r\n
\t\t\toLink.href = sLnkUrl ;\r\n
\t\telse\t\t\t// Creating a new link.\r\n
\t\t{\r\n
\t\t\tif ( !bHasImage )\r\n
\t\t\t\toEditor.FCKSelection.SelectNode( oImage ) ;\r\n
\r\n
\t\t\toLink = oEditor.FCK.CreateLink( sLnkUrl )[0] ;\r\n
\r\n
\t\t\tif ( !bHasImage )\r\n
\t\t\t{\r\n
\t\t\t\toEditor.FCKSelection.SelectNode( oLink ) ;\r\n
\t\t\t\toEditor.FCKSelection.Collapse( false ) ;\r\n
\t\t\t}\r\n
\t\t}\r\n
\r\n
\t\tSetAttribute( oLink, \'_fcksavedurl\', sLnkUrl ) ;\r\n
\t\tSetAttribute( oLink, \'target\', GetE(\'cmbLnkTarget\').value ) ;\r\n
\t}\r\n
\r\n
\treturn true ;\r\n
}\r\n
\r\n
function UpdateImage( e, skipId )\r\n
{\r\n
\te.src = GetE(\'txtUrl\').value ;\r\n
\tSetAttribute( e, "_fcksavedurl", GetE(\'txtUrl\').value ) ;\r\n
\tSetAttribute( e, "alt"   , GetE(\'txtAlt\').value ) ;\r\n
\tSetAttribute( e, "width" , GetE(\'txtWidth\').value ) ;\r\n
\tSetAttribute( e, "height", GetE(\'txtHeight\').value ) ;\r\n
\tSetAttribute( e, "vspace", GetE(\'txtVSpace\').value ) ;\r\n
\tSetAttribute( e, "hspace", GetE(\'txtHSpace\').value ) ;\r\n
\tSetAttribute( e, "border", GetE(\'txtBorder\').value ) ;\r\n
\tSetAttribute( e, "align" , GetE(\'cmbAlign\').value ) ;\r\n
\r\n
\t// Advances Attributes\r\n
\r\n
\tif ( ! skipId )\r\n
\t\tSetAttribute( e, \'id\', GetE(\'txtAttId\').value ) ;\r\n
\r\n
\tSetAttribute( e, \'dir\'\t\t, GetE(\'cmbAttLangDir\').value ) ;\r\n
\tSetAttribute( e, \'lang\'\t\t, GetE(\'txtAttLangCode\').value ) ;\r\n
\tSetAttribute( e, \'title\'\t, GetE(\'txtAttTitle\').value ) ;\r\n
\tSetAttribute( e, \'longDesc\'\t, GetE(\'txtLongDesc\').value ) ;\r\n
\r\n
\tif ( oEditor.FCKBrowserInfo.IsIE )\r\n
\t{\r\n
\t\te.className = GetE(\'txtAttClasses\').value ;\r\n
\t\te.style.cssText = GetE(\'txtAttStyle\').value ;\r\n
\t}\r\n
\telse\r\n
\t{\r\n
\t\tSetAttribute( e, \'class\'\t, GetE(\'txtAttClasses\').value ) ;\r\n
\t\tSetAttribute( e, \'style\', GetE(\'txtAttStyle\').value ) ;\r\n
\t}\r\n
}\r\n
\r\n
var eImgPreview ;\r\n
var eImgPreviewLink ;\r\n
\r\n
function SetPreviewElements( imageElement, linkElement )\r\n
{\r\n
\teImgPreview = imageElement ;\r\n
\teImgPreviewLink = linkElement ;\r\n
\r\n
\tUpdatePreview() ;\r\n
\tUpdateOriginal() ;\r\n
\r\n
\tbPreviewInitialized = true ;\r\n
}\r\n
\r\n
function UpdatePreview()\r\n
{\r\n
\tif ( !eImgPreview || !eImgPreviewLink )\r\n
\t\treturn ;\r\n
\r\n
\tif ( GetE(\'txtUrl\').value.length == 0 )\r\n
\t\teImgPreviewLink.style.display = \'none\' ;\r\n
\telse\r\n
\t{\r\n
\t\tUpdateImage( eImgPreview, true ) ;\r\n
\r\n
\t\tif ( GetE(\'txtLnkUrl\').value.Trim().length > 0 )\r\n
\t\t\teImgPreviewLink.href = \'javascript:void(null);\' ;\r\n
\t\telse\r\n
\t\t\tSetAttribute( eImgPreviewLink, \'href\', \'\' ) ;\r\n
\r\n
\t\teImgPreviewLink.style.display = \'\' ;\r\n
\t}\r\n
}\r\n
\r\n
var bLockRatio = true ;\r\n
\r\n
function SwitchLock( lockButton )\r\n
{\r\n
\tbLockRatio = !bLockRatio ;\r\n
\tlockButton.className = bLockRatio ? \'BtnLocked\' : \'BtnUnlocked\' ;\r\n
\tlockButton.title = bLockRatio ? \'Lock sizes\' : \'Unlock sizes\' ;\r\n
\r\n
\tif ( bLockRatio )\r\n
\t{\r\n
\t\tif ( GetE(\'txtWidth\').value.length > 0 )\r\n
\t\t\tOnSizeChanged( \'Width\', GetE(\'txtWidth\').value ) ;\r\n
\t\telse\r\n
\t\t\tOnSizeChanged( \'Height\', GetE(\'txtHeight\').value ) ;\r\n
\t}\r\n
}\r\n
\r\n
// Fired when the width or height input texts change\r\n
function OnSizeChanged( dimension, value )\r\n
{\r\n
\t// Verifies if the aspect ration has to be maintained\r\n
\tif ( oImageOriginal && bLockRatio )\r\n
\t{\r\n
\t\tvar e = dimension == \'Width\' ? GetE(\'txtHeight\') : GetE(\'txtWidth\') ;\r\n
\r\n
\t\tif ( value.length == 0 || isNaN( value ) )\r\n
\t\t{\r\n
\t\t\te.value = \'\' ;\r\n
\t\t\treturn ;\r\n
\t\t}\r\n
\r\n
\t\tif ( dimension == \'Width\' )\r\n
\t\t\tvalue = value == 0 ? 0 : Math.round( oImageOriginal.height * ( value  / oImageOriginal.width ) ) ;\r\n
\t\telse\r\n
\t\t\tvalue = value == 0 ? 0 : Math.round( oImageOriginal.width  * ( value / oImageOriginal.height ) ) ;\r\n
\r\n
\t\tif ( !isNaN( value ) )\r\n
\t\t\te.value = value ;\r\n
\t}\r\n
\r\n
\tUpdatePreview() ;\r\n
}\r\n
\r\n
// Fired when the Reset Size button is clicked\r\n
function ResetSizes()\r\n
{\r\n
\tif ( ! oImageOriginal ) return ;\r\n
\tif ( oEditor.FCKBrowserInfo.IsGecko && !oImageOriginal.complete )\r\n
\t{\r\n
\t\tsetTimeout( ResetSizes, 50 ) ;\r\n
\t\treturn ;\r\n
\t}\r\n
\r\n
\tGetE(\'txtWidth\').value  = oImageOriginal.width ;\r\n
\tGetE(\'txtHeight\').value = oImageOriginal.height ;\r\n
\r\n
\tUpdatePreview() ;\r\n
}\r\n
\r\n
function BrowseServer()\r\n
{\r\n
\tOpenServerBrowser(\r\n
\t\t\'Image\',\r\n
\t\tFCKConfig.ImageBrowserURL,\r\n
\t\tFCKConfig.ImageBrowserWindowWidth,\r\n
\t\tFCKConfig.ImageBrowserWindowHeight ) ;\r\n
}\r\n
\r\n
function LnkBrowseServer()\r\n
{\r\n
\tOpenServerBrowser(\r\n
\t\t\'Link\',\r\n
\t\tFCKConfig.LinkBrowserURL,\r\n
\t\tFCKConfig.LinkBrowserWindowWidth,\r\n
\t\tFCKConfig.LinkBrowserWindowHeight ) ;\r\n
}\r\n
\r\n
function OpenServerBrowser( type, url, width, height )\r\n
{\r\n
\tsActualBrowser = type ;\r\n
\tOpenFileBrowser( url, width, height ) ;\r\n
}\r\n
\r\n
var sActualBrowser ;\r\n
\r\n
function SetUrl( url, width, height, alt )\r\n
{\r\n
\tif ( sActualBrowser == \'Link\' )\r\n
\t{\r\n
\t\tGetE(\'txtLnkUrl\').value = url ;\r\n
\t\tUpdatePreview() ;\r\n
\t}\r\n
\telse\r\n
\t{\r\n
\t\tGetE(\'txtUrl\').value = url ;\r\n
\t\tGetE(\'txtWidth\').value = width ? width : \'\' ;\r\n
\t\tGetE(\'txtHeight\').value = height ? height : \'\' ;\r\n
\r\n
\t\tif ( alt )\r\n
\t\t\tGetE(\'txtAlt\').value = alt;\r\n
\r\n
\t\tUpdatePreview() ;\r\n
\t\tUpdateOriginal( true ) ;\r\n
\t}\r\n
\r\n
\tdialog.SetSelectedTab( \'Info\' ) ;\r\n
}\r\n
\r\n
function OnUploadCompleted( errorNumber, fileUrl, fileName, customMsg )\r\n
{\r\n
\t// Remove animation\r\n
\twindow.parent.Throbber.Hide() ;\r\n
\tGetE( \'divUpload\' ).style.display  = \'\' ;\r\n
\r\n
\tswitch ( errorNumber )\r\n
\t{\r\n
\t\tcase 0 :\t// No errors\r\n
\t\t\talert( \'Your file has been successfully uploaded\' ) ;\r\n
\t\t\tbreak ;\r\n
\t\tcase 1 :\t// Custom error\r\n
\t\t\talert( customMsg ) ;\r\n
\t\t\treturn ;\r\n
\t\tcase 101 :\t// Custom warning\r\n
\t\t\talert( customMsg ) ;\r\n
\t\t\tbreak ;\r\n
\t\tcase 201 :\r\n
\t\t\talert( \'A file with the same name is already available. The uploaded file has been renamed to "\' + fileName + \'"\' ) ;\r\n
\t\t\tbreak ;\r\n
\t\tcase 202 :\r\n
\t\t\talert( \'Invalid file type\' ) ;\r\n
\t\t\treturn ;\r\n
\t\tcase 203 :\r\n
\t\t\talert( "Security error. You probably don\'t have enough permissions to upload. Please check your server." ) ;\r\n
\t\t\treturn ;\r\n
\t\tcase 500 :\r\n
\t\t\talert( \'The connector is disabled\' ) ;\r\n
\t\t\tbreak ;\r\n
\t\tdefault :\r\n
\t\t\talert( \'Error on file upload. Error number: \' + errorNumber ) ;\r\n
\t\t\treturn ;\r\n
\t}\r\n
\r\n
\tsActualBrowser = \'\' ;\r\n
\tSetUrl( fileUrl ) ;\r\n
\tGetE(\'frmUpload\').reset() ;\r\n
}\r\n
\r\n
var oUploadAllowedExtRegex\t= new RegExp( FCKConfig.ImageUploadAllowedExtensions, \'i\' ) ;\r\n
var oUploadDeniedExtRegex\t= new RegExp( FCKConfig.ImageUploadDeniedExtensions, \'i\' ) ;\r\n
\r\n
function CheckUpload()\r\n
{\r\n
\tvar sFile = GetE(\'txtUploadFile\').value ;\r\n
\r\n
\tif ( sFile.length == 0 )\r\n
\t{\r\n
\t\talert( \'Please select a file to upload\' ) ;\r\n
\t\treturn false ;\r\n
\t}\r\n
\r\n
\tif ( ( FCKConfig.ImageUploadAllowedExtensions.length > 0 && !oUploadAllowedExtRegex.test( sFile ) ) ||\r\n
\t\t( FCKConfig.ImageUploadDeniedExtensions.length > 0 && oUploadDeniedExtRegex.test( sFile ) ) )\r\n
\t{\r\n
\t\tOnUploadCompleted( 202 ) ;\r\n
\t\treturn false ;\r\n
\t}\r\n
\r\n
\t// Show animation\r\n
\twindow.parent.Throbber.Show( 100 ) ;\r\n
\tGetE( \'divUpload\' ).style.display  = \'none\' ;\r\n
\r\n
\treturn true ;\r\n
}\r\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>13079</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
