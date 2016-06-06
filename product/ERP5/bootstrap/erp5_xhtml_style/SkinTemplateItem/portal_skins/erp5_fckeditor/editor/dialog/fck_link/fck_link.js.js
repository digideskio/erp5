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
            <value> <string>fck_link.js</string> </value>
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
 * Scripts related to the Link dialog window (see fck_link.html).\r\n
 */\r\n
\r\n
var dialog\t= window.parent ;\r\n
var oEditor = dialog.InnerDialogLoaded() ;\r\n
\r\n
var FCK\t\t\t= oEditor.FCK ;\r\n
var FCKLang\t\t= oEditor.FCKLang ;\r\n
var FCKConfig\t= oEditor.FCKConfig ;\r\n
var FCKRegexLib\t= oEditor.FCKRegexLib ;\r\n
var FCKTools\t= oEditor.FCKTools ;\r\n
\r\n
//#### Dialog Tabs\r\n
\r\n
// Set the dialog tabs.\r\n
dialog.AddTab( \'Info\', FCKLang.DlgLnkInfoTab ) ;\r\n
\r\n
if ( !FCKConfig.LinkDlgHideTarget )\r\n
\tdialog.AddTab( \'Target\', FCKLang.DlgLnkTargetTab, true ) ;\r\n
\r\n
if ( FCKConfig.LinkUpload )\r\n
\tdialog.AddTab( \'Upload\', FCKLang.DlgLnkUpload, true ) ;\r\n
\r\n
if ( !FCKConfig.LinkDlgHideAdvanced )\r\n
\tdialog.AddTab( \'Advanced\', FCKLang.DlgAdvancedTag ) ;\r\n
\r\n
// Function called when a dialog tag is selected.\r\n
function OnDialogTabChange( tabCode )\r\n
{\r\n
\tShowE(\'divInfo\'\t\t, ( tabCode == \'Info\' ) ) ;\r\n
\tShowE(\'divTarget\'\t, ( tabCode == \'Target\' ) ) ;\r\n
\tShowE(\'divUpload\'\t, ( tabCode == \'Upload\' ) ) ;\r\n
\tShowE(\'divAttribs\'\t, ( tabCode == \'Advanced\' ) ) ;\r\n
\r\n
\tdialog.SetAutoSize( true ) ;\r\n
}\r\n
\r\n
//#### Regular Expressions library.\r\n
var oRegex = new Object() ;\r\n
\r\n
oRegex.UriProtocol = /^(((http|https|ftp|news):\\/\\/)|mailto:)/gi ;\r\n
\r\n
oRegex.UrlOnChangeProtocol = /^(http|https|ftp|news):\\/\\/(?=.)/gi ;\r\n
\r\n
oRegex.UrlOnChangeTestOther = /^((javascript:)|[#\\/\\.])/gi ;\r\n
\r\n
oRegex.ReserveTarget = /^_(blank|self|top|parent)$/i ;\r\n
\r\n
oRegex.PopupUri = /^javascript:void\\(\\s*window.open\\(\\s*\'([^\']+)\'\\s*,\\s*(?:\'([^\']*)\'|null)\\s*,\\s*\'([^\']*)\'\\s*\\)\\s*\\)\\s*$/ ;\r\n
\r\n
// Accessible popups\r\n
oRegex.OnClickPopup = /^\\s*on[cC]lick="\\s*window.open\\(\\s*this\\.href\\s*,\\s*(?:\'([^\']*)\'|null)\\s*,\\s*\'([^\']*)\'\\s*\\)\\s*;\\s*return\\s*false;*\\s*"$/ ;\r\n
\r\n
oRegex.PopupFeatures = /(?:^|,)([^=]+)=(\\d+|yes|no)/gi ;\r\n
\r\n
//#### Parser Functions\r\n
\r\n
var oParser = new Object() ;\r\n
\r\n
// This method simply returns the two inputs in numerical order. You can even\r\n
// provide strings, as the method would parseInt() the values.\r\n
oParser.SortNumerical = function(a, b)\r\n
{\r\n
\treturn parseInt( a, 10 ) - parseInt( b, 10 ) ;\r\n
}\r\n
\r\n
oParser.ParseEMailParams = function(sParams)\r\n
{\r\n
\t// Initialize the oEMailParams object.\r\n
\tvar oEMailParams = new Object() ;\r\n
\toEMailParams.Subject = \'\' ;\r\n
\toEMailParams.Body = \'\' ;\r\n
\r\n
\tvar aMatch = sParams.match( /(^|^\\?|&)subject=([^&]+)/i ) ;\r\n
\tif ( aMatch ) oEMailParams.Subject = decodeURIComponent( aMatch[2] ) ;\r\n
\r\n
\taMatch = sParams.match( /(^|^\\?|&)body=([^&]+)/i ) ;\r\n
\tif ( aMatch ) oEMailParams.Body = decodeURIComponent( aMatch[2] ) ;\r\n
\r\n
\treturn oEMailParams ;\r\n
}\r\n
\r\n
// This method returns either an object containing the email info, or FALSE\r\n
// if the parameter is not an email link.\r\n
oParser.ParseEMailUri = function( sUrl )\r\n
{\r\n
\t// Initializes the EMailInfo object.\r\n
\tvar oEMailInfo = new Object() ;\r\n
\toEMailInfo.Address = \'\' ;\r\n
\toEMailInfo.Subject = \'\' ;\r\n
\toEMailInfo.Body = \'\' ;\r\n
\r\n
\tvar aLinkInfo = sUrl.match( /^(\\w+):(.*)$/ ) ;\r\n
\tif ( aLinkInfo && aLinkInfo[1] == \'mailto\' )\r\n
\t{\r\n
\t\t// This seems to be an unprotected email link.\r\n
\t\tvar aParts = aLinkInfo[2].match( /^([^\\?]+)\\??(.+)?/ ) ;\r\n
\t\tif ( aParts )\r\n
\t\t{\r\n
\t\t\t// Set the e-mail address.\r\n
\t\t\toEMailInfo.Address = aParts[1] ;\r\n
\r\n
\t\t\t// Look for the optional e-mail parameters.\r\n
\t\t\tif ( aParts[2] )\r\n
\t\t\t{\r\n
\t\t\t\tvar oEMailParams = oParser.ParseEMailParams( aParts[2] ) ;\r\n
\t\t\t\toEMailInfo.Subject = oEMailParams.Subject ;\r\n
\t\t\t\toEMailInfo.Body = oEMailParams.Body ;\r\n
\t\t\t}\r\n
\t\t}\r\n
\t\treturn oEMailInfo ;\r\n
\t}\r\n
\telse if ( aLinkInfo && aLinkInfo[1] == \'javascript\' )\r\n
\t{\r\n
\t\t// This may be a protected email.\r\n
\r\n
\t\t// Try to match the url against the EMailProtectionFunction.\r\n
\t\tvar func = FCKConfig.EMailProtectionFunction ;\r\n
\t\tif ( func != null )\r\n
\t\t{\r\n
\t\t\ttry\r\n
\t\t\t{\r\n
\t\t\t\t// Escape special chars.\r\n
\t\t\t\tfunc = func.replace( /([\\/^$*+.?()\\[\\]])/g, \'\\\\$1\' ) ;\r\n
\r\n
\t\t\t\t// Define the possible keys.\r\n
\t\t\t\tvar keys = new Array(\'NAME\', \'DOMAIN\', \'SUBJECT\', \'BODY\') ;\r\n
\r\n
\t\t\t\t// Get the order of the keys (hold them in the array <pos>) and\r\n
\t\t\t\t// the function replaced by regular expression patterns.\r\n
\t\t\t\tvar sFunc = func ;\r\n
\t\t\t\tvar pos = new Array() ;\r\n
\t\t\t\tfor ( var i = 0 ; i < keys.length ; i ++ )\r\n
\t\t\t\t{\r\n
\t\t\t\t\tvar rexp = new RegExp( keys[i] ) ;\r\n
\t\t\t\t\tvar p = func.search( rexp ) ;\r\n
\t\t\t\t\tif ( p >= 0 )\r\n
\t\t\t\t\t{\r\n
\t\t\t\t\t\tsFunc = sFunc.replace( rexp, \'\\\'([^\\\']*)\\\'\' ) ;\r\n
\t\t\t\t\t\tpos[pos.length] = p + \':\' + keys[i] ;\r\n
\t\t\t\t\t}\r\n
\t\t\t\t}\r\n
\r\n
\t\t\t\t// Sort the available keys.\r\n
\t\t\t\tpos.sort( oParser.SortNumerical ) ;\r\n
\r\n
\t\t\t\t// Replace the excaped single quotes in the url, such they do\r\n
\t\t\t\t// not affect the regexp afterwards.\r\n
\t\t\t\taLinkInfo[2] = aLinkInfo[2].replace( /\\\\\'/g, \'###SINGLE_QUOTE###\' ) ;\r\n
\r\n
\t\t\t\t// Create the regexp and execute it.\r\n
\t\t\t\tvar rFunc = new RegExp( \'^\' + sFunc + \'$\' ) ;\r\n
\t\t\t\tvar aMatch = rFunc.exec( aLinkInfo[2] ) ;\r\n
\t\t\t\tif ( aMatch )\r\n
\t\t\t\t{\r\n
\t\t\t\t\tvar aInfo = new Array();\r\n
\t\t\t\t\tfor ( var i = 1 ; i < aMatch.length ; i ++ )\r\n
\t\t\t\t\t{\r\n
\t\t\t\t\t\tvar k = pos[i-1].match(/^\\d+:(.+)$/) ;\r\n
\t\t\t\t\t\taInfo[k[1]] = aMatch[i].replace(/###SINGLE_QUOTE###/g, \'\\\'\') ;\r\n
\t\t\t\t\t}\r\n
\r\n
\t\t\t\t\t// Fill the EMailInfo object that will be returned\r\n
\t\t\t\t\toEMailInfo.Address = aInfo[\'NAME\'] + \'@\' + aInfo[\'DOMAIN\'] ;\r\n
\t\t\t\t\toEMailInfo.Subject = decodeURIComponent( aInfo[\'SUBJECT\'] ) ;\r\n
\t\t\t\t\toEMailInfo.Body = decodeURIComponent( aInfo[\'BODY\'] ) ;\r\n
\r\n
\t\t\t\t\treturn oEMailInfo ;\r\n
\t\t\t\t}\r\n
\t\t\t}\r\n
\t\t\tcatch (e)\r\n
\t\t\t{\r\n
\t\t\t}\r\n
\t\t}\r\n
\r\n
\t\t// Try to match the email against the encode protection.\r\n
\t\tvar aMatch = aLinkInfo[2].match( /^(?:void\\()?location\\.href=\'mailto:\'\\+(String\\.fromCharCode\\([\\d,]+\\))\\+\'(.*)\'\\)?$/ ) ;\r\n
\t\tif ( aMatch )\r\n
\t\t{\r\n
\t\t\t// The link is encoded\r\n
\t\t\toEMailInfo.Address = eval( aMatch[1] ) ;\r\n
\t\t\tif ( aMatch[2] )\r\n
\t\t\t{\r\n
\t\t\t\tvar oEMailParams = oParser.ParseEMailParams( aMatch[2] ) ;\r\n
\t\t\t\toEMailInfo.Subject = oEMailParams.Subject ;\r\n
\t\t\t\toEMailInfo.Body = oEMailParams.Body ;\r\n
\t\t\t}\r\n
\t\t\treturn oEMailInfo ;\r\n
\t\t}\r\n
\t}\r\n
\treturn false;\r\n
}\r\n
\r\n
oParser.CreateEMailUri = function( address, subject, body )\r\n
{\r\n
\t// Switch for the EMailProtection setting.\r\n
\tswitch ( FCKConfig.EMailProtection )\r\n
\t{\r\n
\t\tcase \'function\' :\r\n
\t\t\tvar func = FCKConfig.EMailProtectionFunction ;\r\n
\t\t\tif ( func == null )\r\n
\t\t\t{\r\n
\t\t\t\tif ( FCKConfig.Debug )\r\n
\t\t\t\t{\r\n
\t\t\t\t\talert(\'EMailProtection alert!\\nNo function defined. Please set "FCKConfig.EMailProtectionFunction"\') ;\r\n
\t\t\t\t}\r\n
\t\t\t\treturn \'\';\r\n
\t\t\t}\r\n
\r\n
\t\t\t// Split the email address into name and domain parts.\r\n
\t\t\tvar aAddressParts = address.split( \'@\', 2 ) ;\r\n
\t\t\tif ( aAddressParts[1] == undefined )\r\n
\t\t\t{\r\n
\t\t\t\taAddressParts[1] = \'\' ;\r\n
\t\t\t}\r\n
\r\n
\t\t\t// Replace the keys by their values (embedded in single quotes).\r\n
\t\t\tfunc = func.replace(/NAME/g, "\'" + aAddressParts[0].replace(/\'/g, \'\\\\\\\'\') + "\'") ;\r\n
\t\t\tfunc = func.replace(/DOMAIN/g, "\'" + aAddressParts[1].replace(/\'/g, \'\\\\\\\'\') + "\'") ;\r\n
\t\t\tfunc = func.replace(/SUBJECT/g, "\'" + encodeURIComponent( subject ).replace(/\'/g, \'\\\\\\\'\') + "\'") ;\r\n
\t\t\tfunc = func.replace(/BODY/g, "\'" + encodeURIComponent( body ).replace(/\'/g, \'\\\\\\\'\') + "\'") ;\r\n
\r\n
\t\t\treturn \'javascript:\' + func ;\r\n
\r\n
\t\tcase \'encode\' :\r\n
\t\t\tvar aParams = [] ;\r\n
\t\t\tvar aAddressCode = [] ;\r\n
\r\n
\t\t\tif ( subject.length > 0 )\r\n
\t\t\t\taParams.push( \'subject=\'+ encodeURIComponent( subject ) ) ;\r\n
\t\t\tif ( body.length > 0 )\r\n
\t\t\t\taParams.push( \'body=\' + encodeURIComponent( body ) ) ;\r\n
\t\t\tfor ( var i = 0 ; i < address.length ; i++ )\r\n
\t\t\t\taAddressCode.push( address.charCodeAt( i ) ) ;\r\n
\r\n
\t\t\treturn \'javascript:void(location.href=\\\'mailto:\\\'+String.fromCharCode(\' + aAddressCode.join( \',\' ) + \')+\\\'?\' + aParams.join( \'&\' ) + \'\\\')\' ;\r\n
\t}\r\n
\r\n
\t// EMailProtection \'none\'\r\n
\r\n
\tvar sBaseUri = \'mailto:\' + address ;\r\n
\r\n
\tvar sParams = \'\' ;\r\n
\r\n
\tif ( subject.length > 0 )\r\n
\t\tsParams = \'?subject=\' + encodeURIComponent( subject ) ;\r\n
\r\n
\tif ( body.length > 0 )\r\n
\t{\r\n
\t\tsParams += ( sParams.length == 0 ? \'?\' : \'&\' ) ;\r\n
\t\tsParams += \'body=\' + encodeURIComponent( body ) ;\r\n
\t}\r\n
\r\n
\treturn sBaseUri + sParams ;\r\n
}\r\n
\r\n
//#### Initialization Code\r\n
\r\n
// oLink: The actual selected link in the editor.\r\n
var oLink = dialog.Selection.GetSelection().MoveToAncestorNode( \'A\' ) ;\r\n
if ( oLink )\r\n
\tFCK.Selection.SelectNode( oLink ) ;\r\n
\r\n
window.onload = function()\r\n
{\r\n
\t// Translate the dialog box texts.\r\n
\toEditor.FCKLanguageManager.TranslatePage(document) ;\r\n
\r\n
\t// Fill the Anchor Names and Ids combos.\r\n
\tLoadAnchorNamesAndIds() ;\r\n
\r\n
\t// Load the selected link information (if any).\r\n
\tLoadSelection() ;\r\n
\r\n
\t// Update the dialog box.\r\n
\tSetLinkType( GetE(\'cmbLinkType\').value ) ;\r\n
\r\n
\t// Show/Hide the "Browse Server" button.\r\n
\tGetE(\'divBrowseServer\').style.display = FCKConfig.LinkBrowser ? \'\' : \'none\' ;\r\n
\r\n
\t// Show the initial dialog content.\r\n
\tGetE(\'divInfo\').style.display = \'\' ;\r\n
\r\n
\t// Set the actual uploader URL.\r\n
\tif ( FCKConfig.LinkUpload )\r\n
\t\tGetE(\'frmUpload\').action = FCKConfig.LinkUploadURL ;\r\n
\r\n
\t// Set the default target (from configuration).\r\n
\tSetDefaultTarget() ;\r\n
\r\n
\t// Activate the "OK" button.\r\n
\tdialog.SetOkButton( true ) ;\r\n
\r\n
\t// Select the first field.\r\n
\tswitch( GetE(\'cmbLinkType\').value )\r\n
\t{\r\n
\t\tcase \'url\' :\r\n
\t\t\tSelectField( \'txtUrl\' ) ;\r\n
\t\t\tbreak ;\r\n
\t\tcase \'email\' :\r\n
\t\t\tSelectField( \'txtEMailAddress\' ) ;\r\n
\t\t\tbreak ;\r\n
\t\tcase \'anchor\' :\r\n
\t\t\tif ( GetE(\'divSelAnchor\').style.display != \'none\' )\r\n
\t\t\t\tSelectField( \'cmbAnchorName\' ) ;\r\n
\t\t\telse\r\n
\t\t\t\tSelectField( \'cmbLinkType\' ) ;\r\n
\t}\r\n
}\r\n
\r\n
var bHasAnchors ;\r\n
\r\n
function LoadAnchorNamesAndIds()\r\n
{\r\n
\t// Since version 2.0, the anchors are replaced in the DOM by IMGs so the user see the icon\r\n
\t// to edit them. So, we must look for that images now.\r\n
\tvar aAnchors = new Array() ;\r\n
\tvar i ;\r\n
\tvar oImages = oEditor.FCK.EditorDocument.getElementsByTagName( \'IMG\' ) ;\r\n
\tfor( i = 0 ; i < oImages.length ; i++ )\r\n
\t{\r\n
\t\tif ( oImages[i].getAttribute(\'_fckanchor\') )\r\n
\t\t\taAnchors[ aAnchors.length ] = oEditor.FCK.GetRealElement( oImages[i] ) ;\r\n
\t}\r\n
\r\n
\t// Add also real anchors\r\n
\tvar oLinks = oEditor.FCK.EditorDocument.getElementsByTagName( \'A\' ) ;\r\n
\tfor( i = 0 ; i < oLinks.length ; i++ )\r\n
\t{\r\n
\t\tif ( oLinks[i].name && ( oLinks[i].name.length > 0 ) )\r\n
\t\t\taAnchors[ aAnchors.length ] = oLinks[i] ;\r\n
\t}\r\n
\r\n
\tvar aIds = FCKTools.GetAllChildrenIds( oEditor.FCK.EditorDocument.body ) ;\r\n
\r\n
\tbHasAnchors = ( aAnchors.length > 0 || aIds.length > 0 ) ;\r\n
\r\n
\tfor ( i = 0 ; i < aAnchors.length ; i++ )\r\n
\t{\r\n
\t\tvar sName = aAnchors[i].name ;\r\n
\t\tif ( sName && sName.length > 0 )\r\n
\t\t\tFCKTools.AddSelectOption( GetE(\'cmbAnchorName\'), sName, sName ) ;\r\n
\t}\r\n
\r\n
\tfor ( i = 0 ; i < aIds.length ; i++ )\r\n
\t{\r\n
\t\tFCKTools.AddSelectOption( GetE(\'cmbAnchorId\'), aIds[i], aIds[i] ) ;\r\n
\t}\r\n
\r\n
\tShowE( \'divSelAnchor\'\t, bHasAnchors ) ;\r\n
\tShowE( \'divNoAnchor\'\t, !bHasAnchors ) ;\r\n
}\r\n
\r\n
function LoadSelection()\r\n
{\r\n
\tif ( !oLink ) return ;\r\n
\r\n
\tvar sType = \'url\' ;\r\n
\r\n
\t// Get the actual Link href.\r\n
\tvar sHRef = oLink.getAttribute( \'_fcksavedurl\' ) ;\r\n
\tif ( sHRef == null )\r\n
\t\tsHRef = oLink.getAttribute( \'href\' , 2 ) || \'\' ;\r\n
\r\n
\t// Look for a popup javascript link.\r\n
\tvar oPopupMatch = oRegex.PopupUri.exec( sHRef ) ;\r\n
\tif( oPopupMatch )\r\n
\t{\r\n
\t\tGetE(\'cmbTarget\').value = \'popup\' ;\r\n
\t\tsHRef = oPopupMatch[1] ;\r\n
\t\tFillPopupFields( oPopupMatch[2], oPopupMatch[3] ) ;\r\n
\t\tSetTarget( \'popup\' ) ;\r\n
\t}\r\n
\r\n
\t// Accessible popups, the popup data is in the onclick attribute\r\n
\tif ( !oPopupMatch )\r\n
\t{\r\n
\t\tvar onclick = oLink.getAttribute( \'onclick_fckprotectedatt\' ) ;\r\n
\t\tif ( onclick )\r\n
\t\t{\r\n
\t\t\t// Decode the protected string\r\n
\t\t\tonclick = decodeURIComponent( onclick ) ;\r\n
\r\n
\t\t\toPopupMatch = oRegex.OnClickPopup.exec( onclick ) ;\r\n
\t\t\tif( oPopupMatch )\r\n
\t\t\t{\r\n
\t\t\t\tGetE( \'cmbTarget\' ).value = \'popup\' ;\r\n
\t\t\t\tFillPopupFields( oPopupMatch[1], oPopupMatch[2] ) ;\r\n
\t\t\t\tSetTarget( \'popup\' ) ;\r\n
\t\t\t}\r\n
\t\t}\r\n
\t}\r\n
\r\n
\t// Search for the protocol.\r\n
\tvar sProtocol = oRegex.UriProtocol.exec( sHRef ) ;\r\n
\r\n
\t// Search for a protected email link.\r\n
\tvar oEMailInfo = oParser.ParseEMailUri( sHRef );\r\n
\r\n
\tif ( oEMailInfo )\r\n
\t{\r\n
\t\tsType = \'email\' ;\r\n
\r\n
\t\tGetE(\'txtEMailAddress\').value = oEMailInfo.Address ;\r\n
\t\tGetE(\'txtEMailSubject\').value = oEMailInfo.Subject ;\r\n
\t\tGetE(\'txtEMailBody\').value    = oEMailInfo.Body ;\r\n
\t}\r\n
\telse if ( sProtocol )\r\n
\t{\r\n
\t\tsProtocol = sProtocol[0].toLowerCase() ;\r\n
\t\tGetE(\'cmbLinkProtocol\').value = sProtocol ;\r\n
\r\n
\t\t// Remove the protocol and get the remaining URL.\r\n
\t\tvar sUrl = sHRef.replace( oRegex.UriProtocol, \'\' ) ;\r\n
\t\tsType = \'url\' ;\r\n
\t\tGetE(\'txtUrl\').value = sUrl ;\r\n
\t}\r\n
\telse if ( sHRef.substr(0,1) == \'#\' && sHRef.length > 1 )\t// It is an anchor link.\r\n
\t{\r\n
\t\tsType = \'anchor\' ;\r\n
\t\tGetE(\'cmbAnchorName\').value = GetE(\'cmbAnchorId\').value = sHRef.substr(1) ;\r\n
\t}\r\n
\telse\t\t\t\t\t// It is another type of link.\r\n
\t{\r\n
\t\tsType = \'url\' ;\r\n
\r\n
\t\tGetE(\'cmbLinkProtocol\').value = \'\' ;\r\n
\t\tGetE(\'txtUrl\').value = sHRef ;\r\n
\t}\r\n
\r\n
\tif ( !oPopupMatch )\r\n
\t{\r\n
\t\t// Get the target.\r\n
\t\tvar sTarget = oLink.target ;\r\n
\r\n
\t\tif ( sTarget && sTarget.length > 0 )\r\n
\t\t{\r\n
\t\t\tif ( oRegex.ReserveTarget.test( sTarget ) )\r\n
\t\t\t{\r\n
\t\t\t\tsTarget = sTarget.toLowerCase() ;\r\n
\t\t\t\tGetE(\'cmbTarget\').value = sTarget ;\r\n
\t\t\t}\r\n
\t\t\telse\r\n
\t\t\t\tGetE(\'cmbTarget\').value = \'frame\' ;\r\n
\t\t\tGetE(\'txtTargetFrame\').value = sTarget ;\r\n
\t\t}\r\n
\t}\r\n
\r\n
\t// Get Advances Attributes\r\n
\tGetE(\'txtAttId\').value\t\t\t= oLink.id ;\r\n
\tGetE(\'txtAttName\').value\t\t= oLink.name ;\r\n
\tGetE(\'cmbAttLangDir\').value\t\t= oLink.dir ;\r\n
\tGetE(\'txtAttLangCode\').value\t= oLink.lang ;\r\n
\tGetE(\'txtAttAccessKey\').value\t= oLink.accessKey ;\r\n
\tGetE(\'txtAttTabIndex\').value\t= oLink.tabIndex <= 0 ? \'\' : oLink.tabIndex ;\r\n
\tGetE(\'txtAttTitle\').value\t\t= oLink.title ;\r\n
\tGetE(\'txtAttContentType\').value\t= oLink.type ;\r\n
\tGetE(\'txtAttCharSet\').value\t\t= oLink.charset ;\r\n
\r\n
\tvar sClass ;\r\n
\tif ( oEditor.FCKBrowserInfo.IsIE )\r\n
\t{\r\n
\t\tsClass\t= oLink.getAttribute(\'className\',2) || \'\' ;\r\n
\t\t// Clean up temporary classes for internal use:\r\n
\t\tsClass = sClass.replace( FCKRegexLib.FCK_Class, \'\' ) ;\r\n
\r\n
\t\tGetE(\'txtAttStyle\').value\t= oLink.style.cssText ;\r\n
\t}\r\n
\telse\r\n
\t{\r\n
\t\tsClass\t= oLink.getAttribute(\'class\',2) || \'\' ;\r\n
\t\tGetE(\'txtAttStyle\').value\t= oLink.getAttribute(\'style\',2) || \'\' ;\r\n
\t}\r\n
\tGetE(\'txtAttClasses\').value\t= sClass ;\r\n
\r\n
\t// Update the Link type combo.\r\n
\tGetE(\'cmbLinkType\').value = sType ;\r\n
}\r\n
\r\n
//#### Link type selection.\r\n
function SetLinkType( linkType )\r\n
{\r\n
\tShowE(\'divLinkTypeUrl\'\t\t, (linkType == \'url\') ) ;\r\n
\tShowE(\'divLinkTypeAnchor\'\t, (linkType == \'anchor\') ) ;\r\n
\tShowE(\'divLinkTypeEMail\'\t, (linkType == \'email\') ) ;\r\n
\r\n
\tif ( !FCKConfig.LinkDlgHideTarget )\r\n
\t\tdialog.SetTabVisibility( \'Target\'\t, (linkType == \'url\') ) ;\r\n
\r\n
\tif ( FCKConfig.LinkUpload )\r\n
\t\tdialog.SetTabVisibility( \'Upload\'\t, (linkType == \'url\') ) ;\r\n
\r\n
\tif ( !FCKConfig.LinkDlgHideAdvanced )\r\n
\t\tdialog.SetTabVisibility( \'Advanced\'\t, (linkType != \'anchor\' || bHasAnchors) ) ;\r\n
\r\n
\tif ( linkType == \'email\' )\r\n
\t\tdialog.SetAutoSize( true ) ;\r\n
}\r\n
\r\n
//#### Target type selection.\r\n
function SetTarget( targetType )\r\n
{\r\n
\tGetE(\'tdTargetFrame\').style.display\t= ( targetType == \'popup\' ? \'none\' : \'\' ) ;\r\n
\tGetE(\'tdPopupName\').style.display\t=\r\n
\tGetE(\'tablePopupFeatures\').style.display = ( targetType == \'popup\' ? \'\' : \'none\' ) ;\r\n
\r\n
\tswitch ( targetType )\r\n
\t{\r\n
\t\tcase "_blank" :\r\n
\t\tcase "_self" :\r\n
\t\tcase "_parent" :\r\n
\t\tcase "_top" :\r\n
\t\t\tGetE(\'txtTargetFrame\').value = targetType ;\r\n
\t\t\tbreak ;\r\n
\t\tcase "" :\r\n
\t\t\tGetE(\'txtTargetFrame\').value = \'\' ;\r\n
\t\t\tbreak ;\r\n
\t}\r\n
\r\n
\tif ( targetType == \'popup\' )\r\n
\t\tdialog.SetAutoSize( true ) ;\r\n
}\r\n
\r\n
//#### Called while the user types the URL.\r\n
function OnUrlChange()\r\n
{\r\n
\tvar sUrl = GetE(\'txtUrl\').value ;\r\n
\tvar sProtocol = oRegex.UrlOnChangeProtocol.exec( sUrl ) ;\r\n
\r\n
\tif ( sProtocol )\r\n
\t{\r\n
\t\tsUrl = sUrl.substr( sProtocol[0].length ) ;\r\n
\t\tGetE(\'txtUrl\').value = sUrl ;\r\n
\t\tGetE(\'cmbLinkProtocol\').value = sProtocol[0].toLowerCase() ;\r\n
\t}\r\n
\telse if ( oRegex.UrlOnChangeTestOther.test( sUrl ) )\r\n
\t{\r\n
\t\tGetE(\'cmbLinkProtocol\').value = \'\' ;\r\n
\t}\r\n
}\r\n
\r\n
//#### Called while the user types the target name.\r\n
function OnTargetNameChange()\r\n
{\r\n
\tvar sFrame = GetE(\'txtTargetFrame\').value ;\r\n
\r\n
\tif ( sFrame.length == 0 )\r\n
\t\tGetE(\'cmbTarget\').value = \'\' ;\r\n
\telse if ( oRegex.ReserveTarget.test( sFrame ) )\r\n
\t\tGetE(\'cmbTarget\').value = sFrame.toLowerCase() ;\r\n
\telse\r\n
\t\tGetE(\'cmbTarget\').value = \'frame\' ;\r\n
}\r\n
\r\n
// Accessible popups\r\n
function BuildOnClickPopup()\r\n
{\r\n
\tvar sWindowName = "\'" + GetE(\'txtPopupName\').value.replace(/\\W/gi, "") + "\'" ;\r\n
\r\n
\tvar sFeatures = \'\' ;\r\n
\tvar aChkFeatures = document.getElementsByName( \'chkFeature\' ) ;\r\n
\tfor ( var i = 0 ; i < aChkFeatures.length ; i++ )\r\n
\t{\r\n
\t\tif ( i > 0 ) sFeatures += \',\' ;\r\n
\t\tsFeatures += aChkFeatures[i].value + \'=\' + ( aChkFeatures[i].checked ? \'yes\' : \'no\' ) ;\r\n
\t}\r\n
\r\n
\tif ( GetE(\'txtPopupWidth\').value.length > 0 )\tsFeatures += \',width=\' + GetE(\'txtPopupWidth\').value ;\r\n
\tif ( GetE(\'txtPopupHeight\').value.length > 0 )\tsFeatures += \',height=\' + GetE(\'txtPopupHeight\').value ;\r\n
\tif ( GetE(\'txtPopupLeft\').value.length > 0 )\tsFeatures += \',left=\' + GetE(\'txtPopupLeft\').value ;\r\n
\tif ( GetE(\'txtPopupTop\').value.length > 0 )\t\tsFeatures += \',top=\' + GetE(\'txtPopupTop\').value ;\r\n
\r\n
\tif ( sFeatures != \'\' )\r\n
\t\tsFeatures = sFeatures + ",status" ;\r\n
\r\n
\treturn ( "window.open(this.href," + sWindowName + ",\'" + sFeatures + "\'); return false" ) ;\r\n
}\r\n
\r\n
//#### Fills all Popup related fields.\r\n
function FillPopupFields( windowName, features )\r\n
{\r\n
\tif ( windowName )\r\n
\t\tGetE(\'txtPopupName\').value = windowName ;\r\n
\r\n
\tvar oFeatures = new Object() ;\r\n
\tvar oFeaturesMatch ;\r\n
\twhile( ( oFeaturesMatch = oRegex.PopupFeatures.exec( features ) ) != null )\r\n
\t{\r\n
\t\tvar sValue = oFeaturesMatch[2] ;\r\n
\t\tif ( sValue == ( \'yes\' || \'1\' ) )\r\n
\t\t\toFeatures[ oFeaturesMatch[1] ] = true ;\r\n
\t\telse if ( ! isNaN( sValue ) && sValue != 0 )\r\n
\t\t\toFeatures[ oFeaturesMatch[1] ] = sValue ;\r\n
\t}\r\n
\r\n
\t// Update all features check boxes.\r\n
\tvar aChkFeatures = document.getElementsByName(\'chkFeature\') ;\r\n
\tfor ( var i = 0 ; i < aChkFeatures.length ; i++ )\r\n
\t{\r\n
\t\tif ( oFeatures[ aChkFeatures[i].value ] )\r\n
\t\t\taChkFeatures[i].checked = true ;\r\n
\t}\r\n
\r\n
\t// Update position and size text boxes.\r\n
\tif ( oFeatures[\'width\'] )\tGetE(\'txtPopupWidth\').value\t\t= oFeatures[\'width\'] ;\r\n
\tif ( oFeatures[\'height\'] )\tGetE(\'txtPopupHeight\').value\t= oFeatures[\'height\'] ;\r\n
\tif ( oFeatures[\'left\'] )\tGetE(\'txtPopupLeft\').value\t\t= oFeatures[\'left\'] ;\r\n
\tif ( oFeatures[\'top\'] )\t\tGetE(\'txtPopupTop\').value\t\t= oFeatures[\'top\'] ;\r\n
}\r\n
\r\n
//#### The OK button was hit.\r\n
function Ok()\r\n
{\r\n
\tvar sUri, sInnerHtml ;\r\n
\toEditor.FCKUndo.SaveUndoStep() ;\r\n
\r\n
\tswitch ( GetE(\'cmbLinkType\').value )\r\n
\t{\r\n
\t\tcase \'url\' :\r\n
\t\t\tsUri = GetE(\'txtUrl\').value ;\r\n
\r\n
\t\t\tif ( sUri.length == 0 )\r\n
\t\t\t{\r\n
\t\t\t\talert( FCKLang.DlnLnkMsgNoUrl ) ;\r\n
\t\t\t\treturn false ;\r\n
\t\t\t}\r\n
\r\n
\t\t\tsUri = GetE(\'cmbLinkProtocol\').value + sUri ;\r\n
\r\n
\t\t\tbreak ;\r\n
\r\n
\t\tcase \'email\' :\r\n
\t\t\tsUri = GetE(\'txtEMailAddress\').value ;\r\n
\r\n
\t\t\tif ( sUri.length == 0 )\r\n
\t\t\t{\r\n
\t\t\t\talert( FCKLang.DlnLnkMsgNoEMail ) ;\r\n
\t\t\t\treturn false ;\r\n
\t\t\t}\r\n
\r\n
\t\t\tsUri = oParser.CreateEMailUri(\r\n
\t\t\t\tsUri,\r\n
\t\t\t\tGetE(\'txtEMailSubject\').value,\r\n
\t\t\t\tGetE(\'txtEMailBody\').value ) ;\r\n
\t\t\tbreak ;\r\n
\r\n
\t\tcase \'anchor\' :\r\n
\t\t\tvar sAnchor = GetE(\'cmbAnchorName\').value ;\r\n
\t\t\tif ( sAnchor.length == 0 ) sAnchor = GetE(\'cmbAnchorId\').value ;\r\n
\r\n
\t\t\tif ( sAnchor.length == 0 )\r\n
\t\t\t{\r\n
\t\t\t\talert( FCKLang.DlnLnkMsgNoAnchor ) ;\r\n
\t\t\t\treturn false ;\r\n
\t\t\t}\r\n
\r\n
\t\t\tsUri = \'#\' + sAnchor ;\r\n
\t\t\tbreak ;\r\n
\t}\r\n
\r\n
\t// If no link is selected, create a new one (it may result in more than one link creation - #220).\r\n
\tvar aLinks = oLink ? [ oLink ] : oEditor.FCK.CreateLink( sUri, true ) ;\r\n
\r\n
\t// If no selection, no links are created, so use the uri as the link text (by dom, 2006-05-26)\r\n
\tvar aHasSelection = ( aLinks.length > 0 ) ;\r\n
\tif ( !aHasSelection )\r\n
\t{\r\n
\t\tsInnerHtml = sUri;\r\n
\r\n
\t\t// Built a better text for empty links.\r\n
\t\tswitch ( GetE(\'cmbLinkType\').value )\r\n
\t\t{\r\n
\t\t\t// anchor: use old behavior --> return true\r\n
\t\t\tcase \'anchor\':\r\n
\t\t\t\tsInnerHtml = sInnerHtml.replace( /^#/, \'\' ) ;\r\n
\t\t\t\tbreak ;\r\n
\r\n
\t\t\t// url: try to get path\r\n
\t\t\tcase \'url\':\r\n
\t\t\t\tvar oLinkPathRegEx = new RegExp("//?([^?\\"\']+)([?].*)?$") ;\r\n
\t\t\t\tvar asLinkPath = oLinkPathRegEx.exec( sUri ) ;\r\n
\t\t\t\tif (asLinkPath != null)\r\n
\t\t\t\t\tsInnerHtml = asLinkPath[1];  // use matched path\r\n
\t\t\t\tbreak ;\r\n
\r\n
\t\t\t// mailto: try to get email address\r\n
\t\t\tcase \'email\':\r\n
\t\t\t\tsInnerHtml = GetE(\'txtEMailAddress\').value ;\r\n
\t\t\t\tbreak ;\r\n
\t\t}\r\n
\r\n
\t\t// Create a new (empty) anchor.\r\n
\t\taLinks = [ oEditor.FCK.InsertElement( \'a\' ) ] ;\r\n
\t}\r\n
\r\n
\tfor ( var i = 0 ; i < aLinks.length ; i++ )\r\n
\t{\r\n
\t\toLink = aLinks[i] ;\r\n
\r\n
\t\tif ( aHasSelection )\r\n
\t\t\tsInnerHtml = oLink.innerHTML ;\t\t// Save the innerHTML (IE changes it if it is like an URL).\r\n
\r\n
\t\toLink.href = sUri ;\r\n
\t\tSetAttribute( oLink, \'_fcksavedurl\', sUri ) ;\r\n
\r\n
\t\tvar onclick;\r\n
\t\t// Accessible popups\r\n
\t\tif( GetE(\'cmbTarget\').value == \'popup\' )\r\n
\t\t{\r\n
\t\t\tonclick = BuildOnClickPopup() ;\r\n
\t\t\t// Encode the attribute\r\n
\t\t\tonclick = encodeURIComponent( " onclick=\\"" + onclick + "\\"" )  ;\r\n
\t\t\tSetAttribute( oLink, \'onclick_fckprotectedatt\', onclick ) ;\r\n
\t\t}\r\n
\t\telse\r\n
\t\t{\r\n
\t\t\t// Check if the previous onclick was for a popup:\r\n
\t\t\t// In that case remove the onclick handler.\r\n
\t\t\tonclick = oLink.getAttribute( \'onclick_fckprotectedatt\' ) ;\r\n
\t\t\tif ( onclick )\r\n
\t\t\t{\r\n
\t\t\t\t// Decode the protected string\r\n
\t\t\t\tonclick = decodeURIComponent( onclick ) ;\r\n
\r\n
\t\t\t\tif( oRegex.OnClickPopup.test( onclick ) )\r\n
\t\t\t\t\tSetAttribute( oLink, \'onclick_fckprotectedatt\', \'\' ) ;\r\n
\t\t\t}\r\n
\t\t}\r\n
\r\n
\t\toLink.innerHTML = sInnerHtml ;\t\t// Set (or restore) the innerHTML\r\n
\r\n
\t\t// Target\r\n
\t\tif( GetE(\'cmbTarget\').value != \'popup\' )\r\n
\t\t\tSetAttribute( oLink, \'target\', GetE(\'txtTargetFrame\').value ) ;\r\n
\t\telse\r\n
\t\t\tSetAttribute( oLink, \'target\', null ) ;\r\n
\r\n
\t\t// Let\'s set the "id" only for the first link to avoid duplication.\r\n
\t\tif ( i == 0 )\r\n
\t\t\tSetAttribute( oLink, \'id\', GetE(\'txtAttId\').value ) ;\r\n
\r\n
\t\t// Advances Attributes\r\n
\t\tSetAttribute( oLink, \'name\'\t\t, GetE(\'txtAttName\').value ) ;\r\n
\t\tSetAttribute( oLink, \'dir\'\t\t, GetE(\'cmbAttLangDir\').value ) ;\r\n
\t\tSetAttribute( oLink, \'lang\'\t\t, GetE(\'txtAttLangCode\').value ) ;\r\n
\t\tSetAttribute( oLink, \'accesskey\', GetE(\'txtAttAccessKey\').value ) ;\r\n
\t\tSetAttribute( oLink, \'tabindex\'\t, ( GetE(\'txtAttTabIndex\').value > 0 ? GetE(\'txtAttTabIndex\').value : null ) ) ;\r\n
\t\tSetAttribute( oLink, \'title\'\t, GetE(\'txtAttTitle\').value ) ;\r\n
\t\tSetAttribute( oLink, \'type\'\t\t, GetE(\'txtAttContentType\').value ) ;\r\n
\t\tSetAttribute( oLink, \'charset\'\t, GetE(\'txtAttCharSet\').value ) ;\r\n
\r\n
\t\tif ( oEditor.FCKBrowserInfo.IsIE )\r\n
\t\t{\r\n
\t\t\tvar sClass = GetE(\'txtAttClasses\').value ;\r\n
\t\t\t// If it\'s also an anchor add an internal class\r\n
\t\t\tif ( GetE(\'txtAttName\').value.length != 0 )\r\n
\t\t\t\tsClass += \' FCK__AnchorC\' ;\r\n
\t\t\tSetAttribute( oLink, \'className\', sClass ) ;\r\n
\r\n
\t\t\toLink.style.cssText = GetE(\'txtAttStyle\').value ;\r\n
\t\t}\r\n
\t\telse\r\n
\t\t{\r\n
\t\t\tSetAttribute( oLink, \'class\', GetE(\'txtAttClasses\').value ) ;\r\n
\t\t\tSetAttribute( oLink, \'style\', GetE(\'txtAttStyle\').value ) ;\r\n
\t\t}\r\n
\t}\r\n
\r\n
\t// Select the (first) link.\r\n
\toEditor.FCKSelection.SelectNode( aLinks[0] );\r\n
\r\n
\treturn true ;\r\n
}\r\n
\r\n
function BrowseServer()\r\n
{\r\n
\tOpenFileBrowser( FCKConfig.LinkBrowserURL, FCKConfig.LinkBrowserWindowWidth, FCKConfig.LinkBrowserWindowHeight ) ;\r\n
}\r\n
\r\n
function SetUrl( url )\r\n
{\r\n
\tGetE(\'txtUrl\').value = url ;\r\n
\tOnUrlChange() ;\r\n
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
\tSetUrl( fileUrl ) ;\r\n
\tGetE(\'frmUpload\').reset() ;\r\n
}\r\n
\r\n
var oUploadAllowedExtRegex\t= new RegExp( FCKConfig.LinkUploadAllowedExtensions, \'i\' ) ;\r\n
var oUploadDeniedExtRegex\t= new RegExp( FCKConfig.LinkUploadDeniedExtensions, \'i\' ) ;\r\n
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
\tif ( ( FCKConfig.LinkUploadAllowedExtensions.length > 0 && !oUploadAllowedExtRegex.test( sFile ) ) ||\r\n
\t\t( FCKConfig.LinkUploadDeniedExtensions.length > 0 && oUploadDeniedExtRegex.test( sFile ) ) )\r\n
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
\r\n
function SetDefaultTarget()\r\n
{\r\n
\tvar target = FCKConfig.DefaultLinkTarget || \'\' ;\r\n
\r\n
\tif ( oLink || target.length == 0 )\r\n
\t\treturn ;\r\n
\r\n
\tswitch ( target )\r\n
\t{\r\n
\t\tcase \'_blank\' :\r\n
\t\tcase \'_self\' :\r\n
\t\tcase \'_parent\' :\r\n
\t\tcase \'_top\' :\r\n
\t\t\tGetE(\'cmbTarget\').value = target ;\r\n
\t\t\tbreak ;\r\n
\t\tdefault :\r\n
\t\t\tGetE(\'cmbTarget\').value = \'frame\' ;\r\n
\t\t\tbreak ;\r\n
\t}\r\n
\r\n
\tGetE(\'txtTargetFrame\').value = target ;\r\n
}\r\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>25629</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
