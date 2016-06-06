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
            <value> <string>ts83858910.1</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>fckadobeair.js</string> </value>
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
 * Compatibility code for Adobe AIR.\r\n
 */\r\n
\r\n
if ( FCKBrowserInfo.IsAIR )\r\n
{\r\n
\tvar FCKAdobeAIR = (function()\r\n
\t{\r\n
\t\t/*\r\n
\t\t * ### Private functions.\r\n
\t\t */\r\n
\r\n
\t\tvar getDocumentHead = function( doc )\r\n
\t\t{\r\n
\t\t\tvar head ;\r\n
\t\t\tvar heads = doc.getElementsByTagName( \'head\' ) ;\r\n
\r\n
\t\t\tif( heads && heads[0] )\r\n
\t\t\t\thead = heads[0] ;\r\n
\t\t\telse\r\n
\t\t\t{\r\n
\t\t\t\thead = doc.createElement( \'head\' ) ;\r\n
\t\t\t\tdoc.documentElement.insertBefore( head, doc.documentElement.firstChild ) ;\r\n
\t\t\t}\r\n
\r\n
\t\t\treturn head ;\r\n
\t\t} ;\r\n
\r\n
\t\t/*\r\n
\t\t * ### Public interface.\r\n
\t\t */\r\n
\t\treturn {\r\n
\t\t\tFCKeditorAPI_Evaluate : function( parentWindow, script )\r\n
\t\t\t{\r\n
\t\t\t\t// TODO : This one doesn\'t work always. The parent window will\r\n
\t\t\t\t// point to an anonymous function in this window. If this\r\n
\t\t\t\t// window is destroyied the parent window will be pointing to\r\n
\t\t\t\t// an invalid reference.\r\n
\r\n
\t\t\t\t// Evaluate the script in this window.\r\n
\t\t\t\teval( script ) ;\r\n
\r\n
\t\t\t\t// Point the FCKeditorAPI property of the parent window to the\r\n
\t\t\t\t// local reference.\r\n
\t\t\t\tparentWindow.FCKeditorAPI = window.FCKeditorAPI ;\r\n
\t\t\t},\r\n
\r\n
\t\t\tEditingArea_Start : function( doc, html )\r\n
\t\t\t{\r\n
\t\t\t\t// Get the HTML for the <head>.\r\n
\t\t\t\tvar headInnerHtml = html.match( /<head>([\\s\\S]*)<\\/head>/i )[1] ;\r\n
\r\n
\t\t\t\tif ( headInnerHtml && headInnerHtml.length > 0 )\r\n
\t\t\t\t{\r\n
\t\t\t\t\t// Inject the <head> HTML inside a <div>.\r\n
\t\t\t\t\t// Do that before getDocumentHead because WebKit moves\r\n
\t\t\t\t\t// <link css> elements to the <head> at this point.\r\n
\t\t\t\t\tvar div = doc.createElement( \'div\' ) ;\r\n
\t\t\t\t\tdiv.innerHTML = headInnerHtml ;\r\n
\r\n
\t\t\t\t\t// Move the <div> nodes to <head>.\r\n
\t\t\t\t\tFCKDomTools.MoveChildren( div, getDocumentHead( doc ) ) ;\r\n
\t\t\t\t}\r\n
\r\n
\t\t\t\tdoc.body.innerHTML = html.match( /<body>([\\s\\S]*)<\\/body>/i )[1] ;\r\n
\r\n
\t\t\t\t//prevent clicking on hyperlinks and navigating away\r\n
\t\t\t\tdoc.addEventListener(\'click\', function( ev )\r\n
\t\t\t\t\t{\r\n
\t\t\t\t\t\tev.preventDefault() ;\r\n
\t\t\t\t\t\tev.stopPropagation() ;\r\n
\t\t\t\t\t}, true ) ;\r\n
\t\t\t},\r\n
\r\n
\t\t\tPanel_Contructor : function( doc, baseLocation )\r\n
\t\t\t{\r\n
\t\t\t\tvar head = getDocumentHead( doc ) ;\r\n
\r\n
\t\t\t\t// Set the <base> href.\r\n
\t\t\t\thead.appendChild( doc.createElement(\'base\') ).href = baseLocation ;\r\n
\r\n
\t\t\t\tdoc.body.style.margin\t= \'0px\' ;\r\n
\t\t\t\tdoc.body.style.padding\t= \'0px\' ;\r\n
\t\t\t},\r\n
\r\n
\t\t\tToolbarSet_GetOutElement : function( win, outMatch )\r\n
\t\t\t{\r\n
\t\t\t\tvar toolbarTarget = win.parent ;\r\n
\r\n
\t\t\t\tvar targetWindowParts = outMatch[1].split( \'.\' ) ;\r\n
\t\t\t\twhile ( targetWindowParts.length > 0 )\r\n
\t\t\t\t{\r\n
\t\t\t\t\tvar part = targetWindowParts.shift() ;\r\n
\t\t\t\t\tif ( part.length > 0 )\r\n
\t\t\t\t\t\ttoolbarTarget = toolbarTarget[ part ] ;\r\n
\t\t\t\t}\r\n
\r\n
\t\t\t\ttoolbarTarget = toolbarTarget.document.getElementById( outMatch[2] ) ;\r\n
\t\t\t},\r\n
\r\n
\t\t\tToolbarSet_InitOutFrame : function( doc )\r\n
\t\t\t{\r\n
\t\t\t\tvar head = getDocumentHead( doc ) ;\r\n
\r\n
\t\t\t\thead.appendChild( doc.createElement(\'base\') ).href = window.document.location ;\r\n
\r\n
\t\t\t\tvar targetWindow = doc.defaultView;\r\n
\r\n
\t\t\t\ttargetWindow.adjust = function()\r\n
\t\t\t\t{\r\n
\t\t\t\t\ttargetWindow.frameElement.height = doc.body.scrollHeight;\r\n
\t\t\t\t} ;\r\n
\r\n
\t\t\t\ttargetWindow.onresize = targetWindow.adjust ;\r\n
\t\t\t\ttargetWindow.setTimeout( targetWindow.adjust, 0 ) ;\r\n
\r\n
\t\t\t\tdoc.body.style.overflow = \'hidden\';\r\n
\t\t\t\tdoc.body.innerHTML = document.getElementById( \'xToolbarSpace\' ).innerHTML ;\r\n
\t\t\t}\r\n
\t\t} ;\r\n
\t})();\r\n
\r\n
\t/*\r\n
\t * ### Overrides\r\n
\t */\r\n
\t( function()\r\n
\t{\r\n
\t\t// Save references for override reuse.\r\n
\t\tvar _Original_FCKPanel_Window_OnFocus\t= FCKPanel_Window_OnFocus ;\r\n
\t\tvar _Original_FCKPanel_Window_OnBlur\t= FCKPanel_Window_OnBlur ;\r\n
\t\tvar _Original_FCK_StartEditor\t\t\t= FCK.StartEditor ;\r\n
\r\n
\t\tFCKPanel_Window_OnFocus = function( e, panel )\r\n
\t\t{\r\n
\t\t\t// Call the original implementation.\r\n
\t\t\t_Original_FCKPanel_Window_OnFocus.call( this, e, panel ) ;\r\n
\r\n
\t\t\tif ( panel._focusTimer )\r\n
\t\t\t\tclearTimeout( panel._focusTimer ) ;\r\n
\t\t}\r\n
\r\n
\t\tFCKPanel_Window_OnBlur = function( e, panel )\r\n
\t\t{\r\n
\t\t\t// Delay the execution of the original function.\r\n
\t\t\tpanel._focusTimer = FCKTools.SetTimeout( _Original_FCKPanel_Window_OnBlur, 100, this, [ e, panel ] ) ;\r\n
\t\t}\r\n
\r\n
\t\tFCK.StartEditor = function()\r\n
\t\t{\r\n
\t\t\t// Force pointing to the CSS files instead of using the inline CSS cached styles.\r\n
\t\t\twindow.FCK_InternalCSS\t\t\t= FCKConfig.BasePath + \'css/fck_internal.css\' ;\r\n
\t\t\twindow.FCK_ShowTableBordersCSS\t= FCKConfig.BasePath + \'css/fck_showtableborders_gecko.css\' ;\r\n
\r\n
\t\t\t_Original_FCK_StartEditor.apply( this, arguments ) ;\r\n
\t\t}\r\n
\t})();\r\n
}\r\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>4995</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
