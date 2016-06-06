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
            <value> <string>ts68196012.44</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>fckconfig.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

﻿/*\n
 * FCKeditor - The text editor for Internet - http://www.fckeditor.net\n
 * Copyright (C) 2003-2010 Frederico Caldeira Knabben\n
 *\n
 * == BEGIN LICENSE ==\n
 *\n
 * Licensed under the terms of any of the following licenses at your\n
 * choice:\n
 *\n
 *  - GNU General Public License Version 2 or later (the "GPL")\n
 *    http://www.gnu.org/licenses/gpl.html\n
 *\n
 *  - GNU Lesser General Public License Version 2.1 or later (the "LGPL")\n
 *    http://www.gnu.org/licenses/lgpl.html\n
 *\n
 *  - Mozilla Public License Version 1.1 or later (the "MPL")\n
 *    http://www.mozilla.org/MPL/MPL-1.1.html\n
 *\n
 * == END LICENSE ==\n
 *\n
 * Editor configuration settings.\n
 *\n
 * Follow this link for more information:\n
 * http://docs.fckeditor.net/FCKeditor_2.x/Developers_Guide/Configuration/Configuration_Options\n
 */\n
\n
FCKConfig.CustomConfigurationsPath = \'\' ;\n
\n
FCKConfig.EditorAreaCSS = FCKConfig.BasePath + \'css/fck_editorarea.css\' ;\n
FCKConfig.EditorAreaStyles = \'\' ;\n
FCKConfig.ToolbarComboPreviewCSS = \'\' ;\n
\n
FCKConfig.DocType = \'\' ;\n
\n
FCKConfig.BaseHref = \'\' ;\n
\n
FCKConfig.FullPage = false ;\n
\n
// The following option determines whether the "Show Blocks" feature is enabled or not at startup.\n
FCKConfig.StartupShowBlocks = false ;\n
\n
FCKConfig.Debug = false ;\n
FCKConfig.AllowQueryStringDebug = true ;\n
\n
FCKConfig.SkinPath = FCKConfig.BasePath + \'skins/default/\' ;\n
FCKConfig.SkinEditorCSS = \'\' ;\t// FCKConfig.SkinPath + "|<minified css>" ;\n
FCKConfig.SkinDialogCSS = \'\' ;\t// FCKConfig.SkinPath + "|<minified css>" ;\n
\n
FCKConfig.PreloadImages = [ FCKConfig.SkinPath + \'images/toolbar.start.gif\', FCKConfig.SkinPath + \'images/toolbar.buttonarrow.gif\' ] ;\n
\n
FCKConfig.PluginsPath = FCKConfig.BasePath + \'plugins/\' ;\n
\n
// FCKConfig.Plugins.Add( \'autogrow\' ) ;\n
// FCKConfig.Plugins.Add( \'dragresizetable\' );\n
FCKConfig.AutoGrowMax = 400 ;\n
\n
// FCKConfig.ProtectedSource.Add( /<%[\\s\\S]*?%>/g ) ;\t// ASP style server side code <%...%>\n
// FCKConfig.ProtectedSource.Add( /<\\?[\\s\\S]*?\\?>/g ) ;\t// PHP style server side code\n
// FCKConfig.ProtectedSource.Add( /(<asp:[^\\>]+>[\\s|\\S]*?<\\/asp:[^\\>]+>)|(<asp:[^\\>]+\\/>)/gi ) ;\t// ASP.Net style tags <asp:control>\n
\n
FCKConfig.AutoDetectLanguage\t= true ;\n
FCKConfig.DefaultLanguage\t\t= \'en\' ;\n
FCKConfig.ContentLangDirection\t= \'ltr\' ;\n
\n
FCKConfig.ProcessHTMLEntities\t= true ;\n
FCKConfig.IncludeLatinEntities\t= true ;\n
FCKConfig.IncludeGreekEntities\t= true ;\n
\n
FCKConfig.ProcessNumericEntities = false ;\n
\n
FCKConfig.AdditionalNumericEntities = \'\'  ;\t\t// Single Quote: "\'"\n
\n
FCKConfig.FillEmptyBlocks\t= true ;\n
\n
FCKConfig.FormatSource\t\t= true ;\n
FCKConfig.FormatOutput\t\t= true ;\n
FCKConfig.FormatIndentator\t= \'    \' ;\n
\n
FCKConfig.EMailProtection = \'none\' ; // none | encode | function\n
FCKConfig.EMailProtectionFunction = \'mt(NAME,DOMAIN,SUBJECT,BODY)\' ;\n
\n
FCKConfig.StartupFocus\t= false ;\n
FCKConfig.ForcePasteAsPlainText\t= false ;\n
FCKConfig.AutoDetectPasteFromWord = true ;\t// IE only.\n
FCKConfig.ShowDropDialog = true ;\n
FCKConfig.ForceSimpleAmpersand\t= false ;\n
FCKConfig.TabSpaces\t\t= 0 ;\n
FCKConfig.ShowBorders\t= true ;\n
FCKConfig.SourcePopup\t= false ;\n
FCKConfig.ToolbarStartExpanded\t= true ;\n
FCKConfig.ToolbarCanCollapse\t= true ;\n
FCKConfig.IgnoreEmptyParagraphValue = true ;\n
FCKConfig.FloatingPanelsZIndex = 10000 ;\n
FCKConfig.HtmlEncodeOutput = false ;\n
\n
FCKConfig.TemplateReplaceAll = true ;\n
FCKConfig.TemplateReplaceCheckbox = true ;\n
\n
FCKConfig.ToolbarLocation = \'In\' ;\n
\n
FCKConfig.ToolbarSets["Default"] = [\n
\t[\'Source\',\'DocProps\',\'-\',\'Save\',\'NewPage\',\'Preview\',\'-\',\'Templates\'],\n
\t[\'Cut\',\'Copy\',\'Paste\',\'PasteText\',\'PasteWord\',\'-\',\'Print\',\'SpellCheck\'],\n
\t[\'Undo\',\'Redo\',\'-\',\'Find\',\'Replace\',\'-\',\'SelectAll\',\'RemoveFormat\'],\n
\t[\'Form\',\'Checkbox\',\'Radio\',\'TextField\',\'Textarea\',\'Select\',\'Button\',\'ImageButton\',\'HiddenField\'],\n
\t\'/\',\n
\t[\'Bold\',\'Italic\',\'Underline\',\'StrikeThrough\',\'-\',\'Subscript\',\'Superscript\'],\n
\t[\'OrderedList\',\'UnorderedList\',\'-\',\'Outdent\',\'Indent\',\'Blockquote\',\'CreateDiv\'],\n
\t[\'JustifyLeft\',\'JustifyCenter\',\'JustifyRight\',\'JustifyFull\'],\n
\t[\'Link\',\'Unlink\',\'Anchor\'],\n
\t[\'Image\',\'Flash\',\'Table\',\'Rule\',\'Smiley\',\'SpecialChar\',\'PageBreak\'],\n
\t\'/\',\n
\t[\'Style\',\'FontFormat\',\'FontName\',\'FontSize\'],\n
\t[\'TextColor\',\'BGColor\'],\n
\t[\'FitWindow\',\'ShowBlocks\',\'-\',\'About\']\t\t// No comma for the last row.\n
] ;\n
\n
FCKConfig.ToolbarSets["Basic"] = [\n
\t[\'Bold\',\'Italic\',\'-\',\'OrderedList\',\'UnorderedList\',\'-\',\'Link\',\'Unlink\',\'-\',\'About\']\n
] ;\n
\n
FCKConfig.EnterMode = \'p\' ;\t\t\t// p | div | br\n
FCKConfig.ShiftEnterMode = \'br\' ;\t// p | div | br\n
\n
FCKConfig.Keystrokes = [\n
\t[ CTRL + 65 /*A*/, true ],\n
\t[ CTRL + 67 /*C*/, true ],\n
\t[ CTRL + 70 /*F*/, true ],\n
\t[ CTRL + 83 /*S*/, true ],\n
\t[ CTRL + 84 /*T*/, true ],\n
\t[ CTRL + 88 /*X*/, true ],\n
\t[ CTRL + 86 /*V*/, \'Paste\' ],\n
\t[ CTRL + 45 /*INS*/, true ],\n
\t[ SHIFT + 45 /*INS*/, \'Paste\' ],\n
\t[ CTRL + 88 /*X*/, \'Cut\' ],\n
\t[ SHIFT + 46 /*DEL*/, \'Cut\' ],\n
\t[ CTRL + 90 /*Z*/, \'Undo\' ],\n
\t[ CTRL + 89 /*Y*/, \'Redo\' ],\n
\t[ CTRL + SHIFT + 90 /*Z*/, \'Redo\' ],\n
\t[ CTRL + 76 /*L*/, \'Link\' ],\n
\t[ CTRL + 66 /*B*/, \'Bold\' ],\n
\t[ CTRL + 73 /*I*/, \'Italic\' ],\n
\t[ CTRL + 85 /*U*/, \'Underline\' ],\n
\t[ CTRL + SHIFT + 83 /*S*/, \'Save\' ],\n
\t[ CTRL + ALT + 13 /*ENTER*/, \'FitWindow\' ],\n
\t[ SHIFT + 32 /*SPACE*/, \'Nbsp\' ]\n
] ;\n
\n
FCKConfig.ContextMenu = [\'Generic\',\'Link\',\'Anchor\',\'Image\',\'Flash\',\'Select\',\'Textarea\',\'Checkbox\',\'Radio\',\'TextField\',\'HiddenField\',\'ImageButton\',\'Button\',\'BulletedList\',\'NumberedList\',\'Table\',\'Form\',\'DivContainer\'] ;\n
FCKConfig.BrowserContextMenuOnCtrl = false ;\n
FCKConfig.BrowserContextMenu = false ;\n
\n
FCKConfig.EnableMoreFontColors = true ;\n
FCKConfig.FontColors = \'000000,993300,333300,003300,003366,000080,333399,333333,800000,FF6600,808000,808080,008080,0000FF,666699,808080,FF0000,FF9900,99CC00,339966,33CCCC,3366FF,800080,999999,FF00FF,FFCC00,FFFF00,00FF00,00FFFF,00CCFF,993366,C0C0C0,FF99CC,FFCC99,FFFF99,CCFFCC,CCFFFF,99CCFF,CC99FF,FFFFFF\' ;\n
\n
FCKConfig.FontFormats\t= \'p;h1;h2;h3;h4;h5;h6;pre;address;div\' ;\n
FCKConfig.FontNames\t\t= \'Arial;Comic Sans MS;Courier New;Tahoma;Times New Roman;Verdana\' ;\n
FCKConfig.FontSizes\t\t= \'smaller;larger;xx-small;x-small;small;medium;large;x-large;xx-large\' ;\n
\n
FCKConfig.StylesXmlPath\t\t= FCKConfig.EditorPath + \'fckstyles.xml\' ;\n
FCKConfig.TemplatesXmlPath\t= FCKConfig.EditorPath + \'fcktemplates.xml\' ;\n
\n
FCKConfig.SpellChecker\t\t\t= \'WSC\' ;\t// \'WSC\' | \'SCAYT\' | \'SpellerPages\' | \'ieSpell\'\n
FCKConfig.IeSpellDownloadUrl\t= \'http://www.iespell.com/download.php\' ;\n
FCKConfig.SpellerPagesServerScript = \'server-scripts/spellchecker.php\' ;\t// Available extension: .php .cfm .pl\n
FCKConfig.FirefoxSpellChecker\t= false ;\n
\n
FCKConfig.MaxUndoLevels = 15 ;\n
\n
FCKConfig.DisableObjectResizing = false ;\n
FCKConfig.DisableFFTableHandles = true ;\n
\n
FCKConfig.LinkDlgHideTarget\t\t= false ;\n
FCKConfig.LinkDlgHideAdvanced\t= false ;\n
\n
FCKConfig.ImageDlgHideLink\t\t= false ;\n
FCKConfig.ImageDlgHideAdvanced\t= false ;\n
\n
FCKConfig.FlashDlgHideAdvanced\t= false ;\n
\n
FCKConfig.ProtectedTags = \'\' ;\n
\n
// This will be applied to the body element of the editor\n
FCKConfig.BodyId = \'\' ;\n
FCKConfig.BodyClass = \'\' ;\n
\n
FCKConfig.DefaultStyleLabel = \'\' ;\n
FCKConfig.DefaultFontFormatLabel = \'\' ;\n
FCKConfig.DefaultFontLabel = \'\' ;\n
FCKConfig.DefaultFontSizeLabel = \'\' ;\n
\n
FCKConfig.DefaultLinkTarget = \'\' ;\n
\n
// The option switches between trying to keep the html structure or do the changes so the content looks like it was in Word\n
FCKConfig.CleanWordKeepsStructure = false ;\n
\n
// Only inline elements are valid.\n
FCKConfig.RemoveFormatTags = \'b,big,code,del,dfn,em,font,i,ins,kbd,q,samp,small,span,strike,strong,sub,sup,tt,u,var\' ;\n
\n
// Attributes that will be removed\n
FCKConfig.RemoveAttributes = \'class,style,lang,width,height,align,hspace,valign\' ;\n
\n
FCKConfig.CustomStyles =\n
{\n
\t\'Red Title\'\t: { Element : \'h3\', Styles : { \'color\' : \'Red\' } }\n
};\n
\n
// Do not add, rename or remove styles here. Only apply definition changes.\n
FCKConfig.CoreStyles =\n
{\n
\t// Basic Inline Styles.\n
\t\'Bold\'\t\t\t: { Element : \'strong\', Overrides : \'b\' },\n
\t\'Italic\'\t\t: { Element : \'em\', Overrides : \'i\' },\n
\t\'Underline\'\t\t: { Element : \'u\' },\n
\t\'StrikeThrough\'\t: { Element : \'strike\' },\n
\t\'Subscript\'\t\t: { Element : \'sub\' },\n
\t\'Superscript\'\t: { Element : \'sup\' },\n
\n
\t// Basic Block Styles (Font Format Combo).\n
\t\'p\'\t\t\t\t: { Element : \'p\' },\n
\t\'div\'\t\t\t: { Element : \'div\' },\n
\t\'pre\'\t\t\t: { Element : \'pre\' },\n
\t\'address\'\t\t: { Element : \'address\' },\n
\t\'h1\'\t\t\t: { Element : \'h1\' },\n
\t\'h2\'\t\t\t: { Element : \'h2\' },\n
\t\'h3\'\t\t\t: { Element : \'h3\' },\n
\t\'h4\'\t\t\t: { Element : \'h4\' },\n
\t\'h5\'\t\t\t: { Element : \'h5\' },\n
\t\'h6\'\t\t\t: { Element : \'h6\' },\n
\n
\t// Other formatting features.\n
\t\'FontFace\' :\n
\t{\n
\t\tElement\t\t: \'span\',\n
\t\tStyles\t\t: { \'font-family\' : \'#("Font")\' },\n
\t\tOverrides\t: [ { Element : \'font\', Attributes : { \'face\' : null } } ]\n
\t},\n
\n
\t\'Size\' :\n
\t{\n
\t\tElement\t\t: \'span\',\n
\t\tStyles\t\t: { \'font-size\' : \'#("Size","fontSize")\' },\n
\t\tOverrides\t: [ { Element : \'font\', Attributes : { \'size\' : null } } ]\n
\t},\n
\n
\t\'Color\' :\n
\t{\n
\t\tElement\t\t: \'span\',\n
\t\tStyles\t\t: { \'color\' : \'#("Color","color")\' },\n
\t\tOverrides\t: [ { Element : \'font\', Attributes : { \'color\' : null } } ]\n
\t},\n
\n
\t\'BackColor\'\t\t: { Element : \'span\', Styles : { \'background-color\' : \'#("Color","color")\' } },\n
\n
\t\'SelectionHighlight\' : { Element : \'span\', Styles : { \'background-color\' : \'navy\', \'color\' : \'white\' } }\n
};\n
\n
// The distance of an indentation step.\n
FCKConfig.IndentLength = 40 ;\n
FCKConfig.IndentUnit = \'px\' ;\n
\n
// Alternatively, FCKeditor allows the use of CSS classes for block indentation.\n
// This overrides the IndentLength/IndentUnit settings.\n
FCKConfig.IndentClasses = [] ;\n
\n
// [ Left, Center, Right, Justified ]\n
FCKConfig.JustifyClasses = [] ;\n
\n
// The following value defines which File Browser connector and Quick Upload\n
// "uploader" to use. It is valid for the default implementaion and it is here\n
// just to make this configuration file cleaner.\n
// It is not possible to change this value using an external file or even\n
// inline when creating the editor instance. In that cases you must set the\n
// values of LinkBrowserURL, ImageBrowserURL and so on.\n
// Custom implementations should just ignore it.\n
var _FileBrowserLanguage\t= \'php\' ;\t// asp | aspx | cfm | lasso | perl | php | py\n
var _QuickUploadLanguage\t= \'php\' ;\t// asp | aspx | cfm | lasso | perl | php | py\n
\n
// Don\'t care about the following two lines. It just calculates the correct connector\n
// extension to use for the default File Browser (Perl uses "cgi").\n
var _FileBrowserExtension = _FileBrowserLanguage == \'perl\' ? \'cgi\' : _FileBrowserLanguage ;\n
var _QuickUploadExtension = _QuickUploadLanguage == \'perl\' ? \'cgi\' : _QuickUploadLanguage ;\n
\n
FCKConfig.LinkBrowser = true ;\n
FCKConfig.LinkBrowserURL = FCKConfig.BasePath + \'filemanager/browser/default/browser.html?Connector=\' + encodeURIComponent( FCKConfig.BasePath + \'filemanager/connectors/\' + _FileBrowserLanguage + \'/connector.\' + _FileBrowserExtension ) ;\n
FCKConfig.LinkBrowserWindowWidth\t= FCKConfig.ScreenWidth * 0.7 ;\t\t// 70%\n
FCKConfig.LinkBrowserWindowHeight\t= FCKConfig.ScreenHeight * 0.7 ;\t// 70%\n
\n
FCKConfig.ImageBrowser = true ;\n
FCKConfig.ImageBrowserURL = FCKConfig.BasePath + \'filemanager/browser/default/browser.html?Type=Image&Connector=\' + encodeURIComponent( FCKConfig.BasePath + \'filemanager/connectors/\' + _FileBrowserLanguage + \'/connector.\' + _FileBrowserExtension ) ;\n
FCKConfig.ImageBrowserWindowWidth  = FCKConfig.ScreenWidth * 0.7 ;\t// 70% ;\n
FCKConfig.ImageBrowserWindowHeight = FCKConfig.ScreenHeight * 0.7 ;\t// 70% ;\n
\n
FCKConfig.FlashBrowser = true ;\n
FCKConfig.FlashBrowserURL = FCKConfig.BasePath + \'filemanager/browser/default/browser.html?Type=Flash&Connector=\' + encodeURIComponent( FCKConfig.BasePath + \'filemanager/connectors/\' + _FileBrowserLanguage + \'/connector.\' + _FileBrowserExtension ) ;\n
FCKConfig.FlashBrowserWindowWidth  = FCKConfig.ScreenWidth * 0.7 ;\t//70% ;\n
FCKConfig.FlashBrowserWindowHeight = FCKConfig.ScreenHeight * 0.7 ;\t//70% ;\n
\n
FCKConfig.LinkUpload = true ;\n
FCKConfig.LinkUploadURL = FCKConfig.BasePath + \'filemanager/connectors/\' + _QuickUploadLanguage + \'/upload.\' + _QuickUploadExtension ;\n
FCKConfig.LinkUploadAllowedExtensions\t= ".(7z|aiff|asf|avi|bmp|csv|doc|fla|flv|gif|gz|gzip|jpeg|jpg|mid|mov|mp3|mp4|mpc|mpeg|mpg|ods|odt|pdf|png|ppt|pxd|qt|ram|rar|rm|rmi|rmvb|rtf|sdc|sitd|swf|sxc|sxw|tar|tgz|tif|tiff|txt|vsd|wav|wma|wmv|xls|xml|zip)$" ;\t\t\t// empty for all\n
FCKConfig.LinkUploadDeniedExtensions\t= "" ;\t// empty for no one\n
\n
FCKConfig.ImageUpload = true ;\n
FCKConfig.ImageUploadURL = FCKConfig.BasePath + \'filemanager/connectors/\' + _QuickUploadLanguage + \'/upload.\' + _QuickUploadExtension + \'?Type=Image\' ;\n
FCKConfig.ImageUploadAllowedExtensions\t= ".(jpg|gif|jpeg|png|bmp)$" ;\t\t// empty for all\n
FCKConfig.ImageUploadDeniedExtensions\t= "" ;\t\t\t\t\t\t\t// empty for no one\n
\n
FCKConfig.FlashUpload = true ;\n
FCKConfig.FlashUploadURL = FCKConfig.BasePath + \'filemanager/connectors/\' + _QuickUploadLanguage + \'/upload.\' + _QuickUploadExtension + \'?Type=Flash\' ;\n
FCKConfig.FlashUploadAllowedExtensions\t= ".(swf|flv)$" ;\t\t// empty for all\n
FCKConfig.FlashUploadDeniedExtensions\t= "" ;\t\t\t\t\t// empty for no one\n
\n
FCKConfig.SmileyPath\t= FCKConfig.BasePath + \'images/smiley/msn/\' ;\n
FCKConfig.SmileyImages\t= [\'regular_smile.gif\',\'sad_smile.gif\',\'wink_smile.gif\',\'teeth_smile.gif\',\'confused_smile.gif\',\'tounge_smile.gif\',\'embaressed_smile.gif\',\'omg_smile.gif\',\'whatchutalkingabout_smile.gif\',\'angry_smile.gif\',\'angel_smile.gif\',\'shades_smile.gif\',\'devil_smile.gif\',\'cry_smile.gif\',\'lightbulb.gif\',\'thumbs_down.gif\',\'thumbs_up.gif\',\'heart.gif\',\'broken_heart.gif\',\'kiss.gif\',\'envelope.gif\'] ;\n
FCKConfig.SmileyColumns = 8 ;\n
FCKConfig.SmileyWindowWidth\t\t= 320 ;\n
FCKConfig.SmileyWindowHeight\t= 210 ;\n
\n
FCKConfig.BackgroundBlockerColor = \'#ffffff\' ;\n
FCKConfig.BackgroundBlockerOpacity = 0.50 ;\n
\n
FCKConfig.MsWebBrowserControlCompat = false ;\n
\n
FCKConfig.PreventSubmitHandler = false ;\n
\n
// toolbar set for erp5_web\n
FCKConfig.ToolbarSets["ERP5WebZopeCmf"] = [\n
  [\'Source\',\'-\',\'Templates\'],\n
  [\'Cut\',\'Copy\',\'Paste\',\'PasteText\',\'PasteWord\',\'-\'],\n
  [\'Undo\',\'Redo\',\'-\',\'Find\',\'Replace\',\'-\',\'SelectAll\',\'RemoveFormat\'],\n
  [\'Bold\',\'Italic\',\'Underline\',\'StrikeThrough\',\'-\',\'Subscript\',\'Superscript\'],\n
  [\'OrderedList\',\'UnorderedList\',\'-\',\'Outdent\',\'Indent\'],\n
  [\'JustifyLeft\',\'JustifyCenter\',\'JustifyRight\',\'JustifyFull\'],\n
  [\'Link\',\'Unlink\',\'Anchor\'],\n
  [\'Image\',\'Table\',\'Rule\',\'SpecialChar\'],\n
  [\'TextColor\',\'BGColor\'],\n
  \'/\',\n
  [\'Style\',\'FontFormat\',\'FontName\',\'FontSize\']\n
];\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>14197</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
