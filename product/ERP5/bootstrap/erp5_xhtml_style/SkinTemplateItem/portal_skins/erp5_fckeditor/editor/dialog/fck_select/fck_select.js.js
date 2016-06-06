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
            <value> <string>ts83858910.02</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>fck_select.js</string> </value>
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
 * Scripts for the fck_select.html page.\r\n
 */\r\n
\r\n
function Select( combo )\r\n
{\r\n
\tvar iIndex = combo.selectedIndex ;\r\n
\r\n
\toListText.selectedIndex\t\t= iIndex ;\r\n
\toListValue.selectedIndex\t= iIndex ;\r\n
\r\n
\tvar oTxtText\t= document.getElementById( "txtText" ) ;\r\n
\tvar oTxtValue\t= document.getElementById( "txtValue" ) ;\r\n
\r\n
\toTxtText.value\t= oListText.value ;\r\n
\toTxtValue.value\t= oListValue.value ;\r\n
}\r\n
\r\n
function Add()\r\n
{\r\n
\tvar oTxtText\t= document.getElementById( "txtText" ) ;\r\n
\tvar oTxtValue\t= document.getElementById( "txtValue" ) ;\r\n
\r\n
\tAddComboOption( oListText, oTxtText.value, oTxtText.value ) ;\r\n
\tAddComboOption( oListValue, oTxtValue.value, oTxtValue.value ) ;\r\n
\r\n
\toListText.selectedIndex = oListText.options.length - 1 ;\r\n
\toListValue.selectedIndex = oListValue.options.length - 1 ;\r\n
\r\n
\toTxtText.value\t= \'\' ;\r\n
\toTxtValue.value\t= \'\' ;\r\n
\r\n
\toTxtText.focus() ;\r\n
}\r\n
\r\n
function Modify()\r\n
{\r\n
\tvar iIndex = oListText.selectedIndex ;\r\n
\r\n
\tif ( iIndex < 0 ) return ;\r\n
\r\n
\tvar oTxtText\t= document.getElementById( "txtText" ) ;\r\n
\tvar oTxtValue\t= document.getElementById( "txtValue" ) ;\r\n
\r\n
\toListText.options[ iIndex ].innerHTML\t= HTMLEncode( oTxtText.value ) ;\r\n
\toListText.options[ iIndex ].value\t\t= oTxtText.value ;\r\n
\r\n
\toListValue.options[ iIndex ].innerHTML\t= HTMLEncode( oTxtValue.value ) ;\r\n
\toListValue.options[ iIndex ].value\t\t= oTxtValue.value ;\r\n
\r\n
\toTxtText.value\t= \'\' ;\r\n
\toTxtValue.value\t= \'\' ;\r\n
\r\n
\toTxtText.focus() ;\r\n
}\r\n
\r\n
function Move( steps )\r\n
{\r\n
\tChangeOptionPosition( oListText, steps ) ;\r\n
\tChangeOptionPosition( oListValue, steps ) ;\r\n
}\r\n
\r\n
function Delete()\r\n
{\r\n
\tRemoveSelectedOptions( oListText ) ;\r\n
\tRemoveSelectedOptions( oListValue ) ;\r\n
}\r\n
\r\n
function SetSelectedValue()\r\n
{\r\n
\tvar iIndex = oListValue.selectedIndex ;\r\n
\tif ( iIndex < 0 ) return ;\r\n
\r\n
\tvar oTxtValue = document.getElementById( "txtSelValue" ) ;\r\n
\r\n
\toTxtValue.value = oListValue.options[ iIndex ].value ;\r\n
}\r\n
\r\n
// Moves the selected option by a number of steps (also negative)\r\n
function ChangeOptionPosition( combo, steps )\r\n
{\r\n
\tvar iActualIndex = combo.selectedIndex ;\r\n
\r\n
\tif ( iActualIndex < 0 )\r\n
\t\treturn ;\r\n
\r\n
\tvar iFinalIndex = iActualIndex + steps ;\r\n
\r\n
\tif ( iFinalIndex < 0 )\r\n
\t\tiFinalIndex = 0 ;\r\n
\r\n
\tif ( iFinalIndex > ( combo.options.length - 1 ) )\r\n
\t\tiFinalIndex = combo.options.length - 1 ;\r\n
\r\n
\tif ( iActualIndex == iFinalIndex )\r\n
\t\treturn ;\r\n
\r\n
\tvar oOption = combo.options[ iActualIndex ] ;\r\n
\tvar sText\t= HTMLDecode( oOption.innerHTML ) ;\r\n
\tvar sValue\t= oOption.value ;\r\n
\r\n
\tcombo.remove( iActualIndex ) ;\r\n
\r\n
\toOption = AddComboOption( combo, sText, sValue, null, iFinalIndex ) ;\r\n
\r\n
\toOption.selected = true ;\r\n
}\r\n
\r\n
// Remove all selected options from a SELECT object\r\n
function RemoveSelectedOptions(combo)\r\n
{\r\n
\t// Save the selected index\r\n
\tvar iSelectedIndex = combo.selectedIndex ;\r\n
\r\n
\tvar oOptions = combo.options ;\r\n
\r\n
\t// Remove all selected options\r\n
\tfor ( var i = oOptions.length - 1 ; i >= 0 ; i-- )\r\n
\t{\r\n
\t\tif (oOptions[i].selected) combo.remove(i) ;\r\n
\t}\r\n
\r\n
\t// Reset the selection based on the original selected index\r\n
\tif ( combo.options.length > 0 )\r\n
\t{\r\n
\t\tif ( iSelectedIndex >= combo.options.length ) iSelectedIndex = combo.options.length - 1 ;\r\n
\t\tcombo.selectedIndex = iSelectedIndex ;\r\n
\t}\r\n
}\r\n
\r\n
// Add a new option to a SELECT object (combo or list)\r\n
function AddComboOption( combo, optionText, optionValue, documentObject, index )\r\n
{\r\n
\tvar oOption ;\r\n
\r\n
\tif ( documentObject )\r\n
\t\toOption = documentObject.createElement("OPTION") ;\r\n
\telse\r\n
\t\toOption = document.createElement("OPTION") ;\r\n
\r\n
\tif ( index != null )\r\n
\t\tcombo.options.add( oOption, index ) ;\r\n
\telse\r\n
\t\tcombo.options.add( oOption ) ;\r\n
\r\n
\toOption.innerHTML = optionText.length > 0 ? HTMLEncode( optionText ) : \'&nbsp;\' ;\r\n
\toOption.value     = optionValue ;\r\n
\r\n
\treturn oOption ;\r\n
}\r\n
\r\n
function HTMLEncode( text )\r\n
{\r\n
\tif ( !text )\r\n
\t\treturn \'\' ;\r\n
\r\n
\ttext = text.replace( /&/g, \'&amp;\' ) ;\r\n
\ttext = text.replace( /</g, \'&lt;\' ) ;\r\n
\ttext = text.replace( />/g, \'&gt;\' ) ;\r\n
\r\n
\treturn text ;\r\n
}\r\n
\r\n
\r\n
function HTMLDecode( text )\r\n
{\r\n
\tif ( !text )\r\n
\t\treturn \'\' ;\r\n
\r\n
\ttext = text.replace( /&gt;/g, \'>\' ) ;\r\n
\ttext = text.replace( /&lt;/g, \'<\' ) ;\r\n
\ttext = text.replace( /&amp;/g, \'&\' ) ;\r\n
\r\n
\treturn text ;\r\n
}\r\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>4773</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
