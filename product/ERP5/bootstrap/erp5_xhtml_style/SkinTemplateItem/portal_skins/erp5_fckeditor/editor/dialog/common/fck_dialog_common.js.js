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
            <value> <string>ts83858910.0</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>fck_dialog_common.js</string> </value>
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
 * Useful functions used by almost all dialog window pages.\r\n
 * Dialogs should link to this file as the very first script on the page.\r\n
 */\r\n
\r\n
// Automatically detect the correct document.domain (#123).\r\n
(function()\r\n
{\r\n
\tvar d = document.domain ;\r\n
\r\n
\twhile ( true )\r\n
\t{\r\n
\t\t// Test if we can access a parent property.\r\n
\t\ttry\r\n
\t\t{\r\n
\t\t\tvar test = window.parent.document.domain ;\r\n
\t\t\tbreak ;\r\n
\t\t}\r\n
\t\tcatch( e ) {}\r\n
\r\n
\t\t// Remove a domain part: www.mytest.example.com => mytest.example.com => example.com ...\r\n
\t\td = d.replace( /.*?(?:\\.|$)/, \'\' ) ;\r\n
\r\n
\t\tif ( d.length == 0 )\r\n
\t\t\tbreak ;\t\t// It was not able to detect the domain.\r\n
\r\n
\t\ttry\r\n
\t\t{\r\n
\t\t\tdocument.domain = d ;\r\n
\t\t}\r\n
\t\tcatch (e)\r\n
\t\t{\r\n
\t\t\tbreak ;\r\n
\t\t}\r\n
\t}\r\n
})() ;\r\n
\r\n
// Attention: FCKConfig must be available in the page.\r\n
function GetCommonDialogCss( prefix )\r\n
{\r\n
\t// CSS minified by http://iceyboard.no-ip.org/projects/css_compressor (see _dev/css_compression.txt).\r\n
\treturn FCKConfig.BasePath + \'dialog/common/\' + \'|.ImagePreviewArea{border:#000 1px solid;overflow:auto;width:100%;height:170px;background-color:#fff}.FlashPreviewArea{border:#000 1px solid;padding:5px;overflow:auto;width:100%;height:170px;background-color:#fff}.BtnReset{float:left;background-position:center center;background-image:url(images/reset.gif);width:16px;height:16px;background-repeat:no-repeat;border:1px none;font-size:1px}.BtnLocked,.BtnUnlocked{float:left;background-position:center center;background-image:url(images/locked.gif);width:16px;height:16px;background-repeat:no-repeat;border:none 1px;font-size:1px}.BtnUnlocked{background-image:url(images/unlocked.gif)}.BtnOver{border:outset 1px;cursor:pointer;cursor:hand}\' ;\r\n
}\r\n
\r\n
// Gets a element by its Id. Used for shorter coding.\r\n
function GetE( elementId )\r\n
{\r\n
\treturn document.getElementById( elementId )  ;\r\n
}\r\n
\r\n
function ShowE( element, isVisible )\r\n
{\r\n
\tif ( typeof( element ) == \'string\' )\r\n
\t\telement = GetE( element ) ;\r\n
\telement.style.display = isVisible ? \'\' : \'none\' ;\r\n
}\r\n
\r\n
function SetAttribute( element, attName, attValue )\r\n
{\r\n
\tif ( attValue == null || attValue.length == 0 )\r\n
\t\telement.removeAttribute( attName, 0 ) ;\t\t\t// 0 : Case Insensitive\r\n
\telse\r\n
\t\telement.setAttribute( attName, attValue, 0 ) ;\t// 0 : Case Insensitive\r\n
}\r\n
\r\n
function GetAttribute( element, attName, valueIfNull )\r\n
{\r\n
\tvar oAtt = element.attributes[attName] ;\r\n
\r\n
\tif ( oAtt == null || !oAtt.specified )\r\n
\t\treturn valueIfNull ? valueIfNull : \'\' ;\r\n
\r\n
\tvar oValue = element.getAttribute( attName, 2 ) ;\r\n
\r\n
\tif ( oValue == null )\r\n
\t\toValue = oAtt.nodeValue ;\r\n
\r\n
\treturn ( oValue == null ? valueIfNull : oValue ) ;\r\n
}\r\n
\r\n
function SelectField( elementId )\r\n
{\r\n
\tvar element = GetE( elementId ) ;\r\n
\telement.focus() ;\r\n
\r\n
\t// element.select may not be available for some fields (like <select>).\r\n
\tif ( element.select )\r\n
\t\telement.select() ;\r\n
}\r\n
\r\n
// Functions used by text fields to accept numbers only.\r\n
var IsDigit = ( function()\r\n
\t{\r\n
\t\tvar KeyIdentifierMap =\r\n
\t\t{\r\n
\t\t\tEnd\t\t\t: 35,\r\n
\t\t\tHome\t\t: 36,\r\n
\t\t\tLeft\t\t: 37,\r\n
\t\t\tRight\t\t: 39,\r\n
\t\t\t\'U+00007F\'\t: 46\t\t// Delete\r\n
\t\t} ;\r\n
\r\n
\t\treturn function ( e )\r\n
\t\t\t{\r\n
\t\t\t\tif ( !e )\r\n
\t\t\t\t\te = event ;\r\n
\r\n
\t\t\t\tvar iCode = ( e.keyCode || e.charCode ) ;\r\n
\r\n
\t\t\t\tif ( !iCode && e.keyIdentifier && ( e.keyIdentifier in KeyIdentifierMap ) )\r\n
\t\t\t\t\t\tiCode = KeyIdentifierMap[ e.keyIdentifier ] ;\r\n
\r\n
\t\t\t\treturn (\r\n
\t\t\t\t\t\t( iCode >= 48 && iCode <= 57 )\t\t// Numbers\r\n
\t\t\t\t\t\t|| (iCode >= 35 && iCode <= 40)\t\t// Arrows, Home, End\r\n
\t\t\t\t\t\t|| iCode == 8\t\t\t\t\t\t// Backspace\r\n
\t\t\t\t\t\t|| iCode == 46\t\t\t\t\t\t// Delete\r\n
\t\t\t\t\t\t|| iCode == 9\t\t\t\t\t\t// Tab\r\n
\t\t\t\t) ;\r\n
\t\t\t}\r\n
\t} )() ;\r\n
\r\n
String.prototype.Trim = function()\r\n
{\r\n
\treturn this.replace( /(^\\s*)|(\\s*$)/g, \'\' ) ;\r\n
}\r\n
\r\n
String.prototype.StartsWith = function( value )\r\n
{\r\n
\treturn ( this.substr( 0, value.length ) == value ) ;\r\n
}\r\n
\r\n
String.prototype.Remove = function( start, length )\r\n
{\r\n
\tvar s = \'\' ;\r\n
\r\n
\tif ( start > 0 )\r\n
\t\ts = this.substring( 0, start ) ;\r\n
\r\n
\tif ( start + length < this.length )\r\n
\t\ts += this.substring( start + length , this.length ) ;\r\n
\r\n
\treturn s ;\r\n
}\r\n
\r\n
String.prototype.ReplaceAll = function( searchArray, replaceArray )\r\n
{\r\n
\tvar replaced = this ;\r\n
\r\n
\tfor ( var i = 0 ; i < searchArray.length ; i++ )\r\n
\t{\r\n
\t\treplaced = replaced.replace( searchArray[i], replaceArray[i] ) ;\r\n
\t}\r\n
\r\n
\treturn replaced ;\r\n
}\r\n
\r\n
function OpenFileBrowser( url, width, height )\r\n
{\r\n
\t// oEditor must be defined.\r\n
\r\n
\tvar iLeft = ( oEditor.FCKConfig.ScreenWidth  - width ) / 2 ;\r\n
\tvar iTop  = ( oEditor.FCKConfig.ScreenHeight - height ) / 2 ;\r\n
\r\n
\tvar sOptions = "toolbar=no,status=no,resizable=yes,dependent=yes,scrollbars=yes" ;\r\n
\tsOptions += ",width=" + width ;\r\n
\tsOptions += ",height=" + height ;\r\n
\tsOptions += ",left=" + iLeft ;\r\n
\tsOptions += ",top=" + iTop ;\r\n
\r\n
\twindow.open( url, \'FCKBrowseWindow\', sOptions ) ;\r\n
}\r\n
\r\n
/**\r\n
 Utility function to create/update an element with a name attribute in IE, so it behaves properly when moved around\r\n
 It also allows to change the name or other special attributes in an existing node\r\n
\toEditor : instance of FCKeditor where the element will be created\r\n
\toOriginal : current element being edited or null if it has to be created\r\n
\tnodeName : string with the name of the element to create\r\n
\toAttributes : Hash object with the attributes that must be set at creation time in IE\r\n
\t\t\t\t\t\t\t\tThose attributes will be set also after the element has been\r\n
\t\t\t\t\t\t\t\tcreated for any other browser to avoid redudant code\r\n
*/\r\n
function CreateNamedElement( oEditor, oOriginal, nodeName, oAttributes )\r\n
{\r\n
\tvar oNewNode ;\r\n
\r\n
\t// IE doesn\'t allow easily to change properties of an existing object,\r\n
\t// so remove the old and force the creation of a new one.\r\n
\tvar oldNode = null ;\r\n
\tif ( oOriginal && oEditor.FCKBrowserInfo.IsIE )\r\n
\t{\r\n
\t\t// Force the creation only if some of the special attributes have changed:\r\n
\t\tvar bChanged = false;\r\n
\t\tfor( var attName in oAttributes )\r\n
\t\t\tbChanged |= ( oOriginal.getAttribute( attName, 2) != oAttributes[attName] ) ;\r\n
\r\n
\t\tif ( bChanged )\r\n
\t\t{\r\n
\t\t\toldNode = oOriginal ;\r\n
\t\t\toOriginal = null ;\r\n
\t\t}\r\n
\t}\r\n
\r\n
\t// If the node existed (and it\'s not IE), then we just have to update its attributes\r\n
\tif ( oOriginal )\r\n
\t{\r\n
\t\toNewNode = oOriginal ;\r\n
\t}\r\n
\telse\r\n
\t{\r\n
\t\t// #676, IE doesn\'t play nice with the name or type attribute\r\n
\t\tif ( oEditor.FCKBrowserInfo.IsIE )\r\n
\t\t{\r\n
\t\t\tvar sbHTML = [] ;\r\n
\t\t\tsbHTML.push( \'<\' + nodeName ) ;\r\n
\t\t\tfor( var prop in oAttributes )\r\n
\t\t\t{\r\n
\t\t\t\tsbHTML.push( \' \' + prop + \'="\' + oAttributes[prop] + \'"\' ) ;\r\n
\t\t\t}\r\n
\t\t\tsbHTML.push( \'>\' ) ;\r\n
\t\t\tif ( !oEditor.FCKListsLib.EmptyElements[nodeName.toLowerCase()] )\r\n
\t\t\t\tsbHTML.push( \'</\' + nodeName + \'>\' ) ;\r\n
\r\n
\t\t\toNewNode = oEditor.FCK.EditorDocument.createElement( sbHTML.join(\'\') ) ;\r\n
\t\t\t// Check if we are just changing the properties of an existing node: copy its properties\r\n
\t\t\tif ( oldNode )\r\n
\t\t\t{\r\n
\t\t\t\tCopyAttributes( oldNode, oNewNode, oAttributes ) ;\r\n
\t\t\t\toEditor.FCKDomTools.MoveChildren( oldNode, oNewNode ) ;\r\n
\t\t\t\toldNode.parentNode.removeChild( oldNode ) ;\r\n
\t\t\t\toldNode = null ;\r\n
\r\n
\t\t\t\tif ( oEditor.FCK.Selection.SelectionData )\r\n
\t\t\t\t{\r\n
\t\t\t\t\t// Trick to refresh the selection object and avoid error in\r\n
\t\t\t\t\t// fckdialog.html Selection.EnsureSelection\r\n
\t\t\t\t\tvar oSel = oEditor.FCK.EditorDocument.selection ;\r\n
\t\t\t\t\toEditor.FCK.Selection.SelectionData = oSel.createRange() ; // Now oSel.type will be \'None\' reflecting the real situation\r\n
\t\t\t\t}\r\n
\t\t\t}\r\n
\t\t\toNewNode = oEditor.FCK.InsertElement( oNewNode ) ;\r\n
\r\n
\t\t\t// FCK.Selection.SelectionData is broken by now since we\'ve\r\n
\t\t\t// deleted the previously selected element. So we need to reassign it.\r\n
\t\t\tif ( oEditor.FCK.Selection.SelectionData )\r\n
\t\t\t{\r\n
\t\t\t\tvar range = oEditor.FCK.EditorDocument.body.createControlRange() ;\r\n
\t\t\t\trange.add( oNewNode ) ;\r\n
\t\t\t\toEditor.FCK.Selection.SelectionData = range ;\r\n
\t\t\t}\r\n
\t\t}\r\n
\t\telse\r\n
\t\t{\r\n
\t\t\toNewNode = oEditor.FCK.InsertElement( nodeName ) ;\r\n
\t\t}\r\n
\t}\r\n
\r\n
\t// Set the basic attributes\r\n
\tfor( var attName in oAttributes )\r\n
\t\toNewNode.setAttribute( attName, oAttributes[attName], 0 ) ;\t// 0 : Case Insensitive\r\n
\r\n
\treturn oNewNode ;\r\n
}\r\n
\r\n
// Copy all the attributes from one node to the other, kinda like a clone\r\n
// But oSkipAttributes is an object with the attributes that must NOT be copied\r\n
function CopyAttributes( oSource, oDest, oSkipAttributes )\r\n
{\r\n
\tvar aAttributes = oSource.attributes ;\r\n
\r\n
\tfor ( var n = 0 ; n < aAttributes.length ; n++ )\r\n
\t{\r\n
\t\tvar oAttribute = aAttributes[n] ;\r\n
\r\n
\t\tif ( oAttribute.specified )\r\n
\t\t{\r\n
\t\t\tvar sAttName = oAttribute.nodeName ;\r\n
\t\t\t// We can set the type only once, so do it with the proper value, not copying it.\r\n
\t\t\tif ( sAttName in oSkipAttributes )\r\n
\t\t\t\tcontinue ;\r\n
\r\n
\t\t\tvar sAttValue = oSource.getAttribute( sAttName, 2 ) ;\r\n
\t\t\tif ( sAttValue == null )\r\n
\t\t\t\tsAttValue = oAttribute.nodeValue ;\r\n
\r\n
\t\t\toDest.setAttribute( sAttName, sAttValue, 0 ) ;\t// 0 : Case Insensitive\r\n
\t\t}\r\n
\t}\r\n
\t// The style:\r\n
\tif ( oSource.style.cssText !== \'\' )\r\n
\t\toDest.style.cssText = oSource.style.cssText ;\r\n
}\r\n
\r\n
/**\r\n
* Replaces a tag with another one, keeping its contents:\r\n
* for example TD --> TH, and TH --> TD.\r\n
* input: the original node, and the new tag name\r\n
* http://www.w3.org/TR/DOM-Level-3-Core/core.html#Document3-renameNode\r\n
*/\r\n
function RenameNode( oNode , newTag )\r\n
{\r\n
\t// TODO: if the browser natively supports document.renameNode call it.\r\n
\t// does any browser currently support it in order to test?\r\n
\r\n
\t// Only rename element nodes.\r\n
\tif ( oNode.nodeType != 1 )\r\n
\t\treturn null ;\r\n
\r\n
\t// If it\'s already correct exit here.\r\n
\tif ( oNode.nodeName == newTag )\r\n
\t\treturn oNode ;\r\n
\r\n
\tvar oDoc = oNode.ownerDocument ;\r\n
\t// Create the new node\r\n
\tvar newNode = oDoc.createElement( newTag ) ;\r\n
\r\n
\t// Copy all attributes\r\n
\tCopyAttributes( oNode, newNode, {} ) ;\r\n
\r\n
\t// Move children to the new node\r\n
\tFCKDomTools.MoveChildren( oNode, newNode ) ;\r\n
\r\n
\t// Finally replace the node and return the new one\r\n
\toNode.parentNode.replaceChild( newNode, oNode ) ;\r\n
\r\n
\treturn newNode ;\r\n
}\r\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>10481</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
