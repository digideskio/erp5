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
            <value> <string>ts86919988.98</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>InternetExplorer.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/* This compressed file is part of Xinha. For uncompressed sources, forum, and bug reports, go to xinha.org */\n
InternetExplorer._pluginInfo={name:"Internet Explorer",origin:"Xinha Core",version:"$LastChangedRevision: 1260 $".replace(/^[^:]*:\\s*(.*)\\s*\\$$/,"$1"),developer:"The Xinha Core Developer Team",developer_url:"$HeadURL: http://svn.xinha.org/trunk/modules/InternetExplorer/InternetExplorer.js $".replace(/^[^:]*:\\s*(.*)\\s*\\$$/,"$1"),sponsor:"",sponsor_url:"",license:"htmlArea"};function InternetExplorer(a){this.editor=a;a.InternetExplorer=this}InternetExplorer.prototype.onKeyPress=function(a){if(this.editor.isShortCut(a)){switch(this.editor.getKey(a).toLowerCase()){case"n":this.editor.execCommand("formatblock",false,"<p>");Xinha._stopEvent(a);return true;break;case"1":case"2":case"3":case"4":case"5":case"6":this.editor.execCommand("formatblock",false,"<h"+this.editor.getKey(a).toLowerCase()+">");Xinha._stopEvent(a);return true;break}}switch(a.keyCode){case 8:case 46:if(this.handleBackspace()){Xinha._stopEvent(a);return true}break;case 9:Xinha._stopEvent(a);return true}return false};InternetExplorer.prototype.handleBackspace=function(){var e=this.editor;var f=e.getSelection();if(f.type=="Control"){var g=e.activeElement(f);Xinha.removeFromParent(g);return true}var d=e.createRange(f);var c=d.duplicate();c.moveStart("character",-1);var b=c.parentElement();if(b!=d.parentElement()&&(/^a$/i.test(b.tagName))){c.collapse(true);c.moveEnd("character",1);c.pasteHTML("");c.select();return true}};InternetExplorer.prototype.inwardHtml=function(a){a=a.replace(/<(\\/?)del(\\s|>|\\/)/ig,"<$1strike$2");a=a.replace(/(<script|<!--)/i,"&nbsp;$1");a=a.replace(/<span[^>]+id="__InsertSpan_Workaround_[a-z]+".*?>([\\s\\S]*?)<\\/span>/i,"$1");return a};InternetExplorer.prototype.outwardHtml=function(a){a=a.replace(/&nbsp;(\\s*)(<script|<!--)/i,"$1$2");a=a.replace(/<span[^>]+id="__InsertSpan_Workaround_[a-z]+".*?>([\\s\\S]*?)<\\/span>/i,"$1");return a};InternetExplorer.prototype.onExecCommand=function(h,d,e){switch(h){case"saveas":var o=null;var c=this.editor;var g=document.createElement("iframe");g.src="about:blank";g.style.display="none";document.body.appendChild(g);try{if(g.contentDocument){o=g.contentDocument}else{o=g.contentWindow.document}}catch(n){}o.open("text/html","replace");var l="";if(c.config.browserQuirksMode===false){var f=\'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\'}else{if(c.config.browserQuirksMode===true){var f=""}else{var f=Xinha.getDoctype(document)}}if(!c.config.fullPage){l+=f+"\\n";l+="<html>\\n";l+="<head>\\n";l+=\'<meta http-equiv="Content-Type" content="text/html; charset=\'+c.config.charSet+\'">\\n\';if(typeof c.config.baseHref!="undefined"&&c.config.baseHref!==null){l+=\'<base href="\'+c.config.baseHref+\'"/>\\n\'}if(typeof c.config.pageStyleSheets!=="undefined"){for(var k=0;k<c.config.pageStyleSheets.length;k++){if(c.config.pageStyleSheets[k].length>0){l+=\'<link rel="stylesheet" type="text/css" href="\'+c.config.pageStyleSheets[k]+\'">\'}}}if(c.config.pageStyle){l+=\'<style type="text/css">\\n\'+c.config.pageStyle+"\\n</style>"}l+="</head>\\n";l+="<body>\\n";l+=c.getEditorContent();l+="</body>\\n";l+="</html>"}else{l=c.getEditorContent();if(l.match(Xinha.RE_doctype)){c.setDoctype(RegExp.$1)}}o.write(l);o.close();o.execCommand(h,d,e);document.body.removeChild(g);return true;break;case"removeformat":var c=this.editor;var b=c.getSelection();var p=c.saveSelection(b);var k,a,j;function m(q){if(q.nodeType!=1){return}q.removeAttribute("style");for(var i=0;i<q.childNodes.length;i++){m(q.childNodes[i])}if((q.tagName.toLowerCase()=="span"&&!q.attributes.length)||q.tagName.toLowerCase()=="font"){q.outerHTML=q.innerHTML}}if(c.selectionEmpty(b)){j=c._doc.body.childNodes;for(k=0;k<j.length;k++){a=j[k];if(a.nodeType!=1){continue}if(a.tagName.toLowerCase()=="span"){newNode=c.convertNode(a,"div");a.parentNode.replaceChild(newNode,a);a=newNode}m(a)}}c._doc.execCommand(h,d,e);c.restoreSelection(p);return true;break}return false};Xinha.prototype.insertNodeAtSelection=function(a){this.insertHTML(a.outerHTML)};Xinha.prototype.getParentElement=function(d){if(typeof d=="undefined"){d=this.getSelection()}var b=this.createRange(d);switch(d.type){case"Text":var a=b.parentElement();while(true){var c=b.duplicate();c.moveToElementText(a);if(c.inRange(b)){break}if((a.nodeType!=1)||(a.tagName.toLowerCase()=="body")){break}a=a.parentElement}return a;case"None":try{return b.parentElement()}catch(f){return this._doc.body}case"Control":return b.item(0);default:return this._doc.body}};Xinha.prototype.activeElement=function(c){if((c===null)||this.selectionEmpty(c)){return null}if(c.type.toLowerCase()=="control"){return c.createRange().item(0)}else{var b=c.createRange();var a=this.getParentElement(c);if(a.innerHTML==b.htmlText){return a}return null}};Xinha.prototype.selectionEmpty=function(a){if(!a){return true}return this.createRange(a).htmlText===""};Xinha.prototype.saveSelection=function(a){return this.createRange(a?a:this.getSelection())};Xinha.prototype.restoreSelection=function(i){if(!i){return}var f=null;if(i.parentElement){f=i.parentElement()}else{f=i.item(0)}var b=this.createRange(this.getSelection());var l=null;if(b.parentElement){l=b.parentElement()}else{l=b.item(0)}var n=function(o){for(var e=o;e;e=e.parentNode){if(e.tagName.toLowerCase()=="html"){return e.parentNode}}return null};if(i.parentElement&&n(f)==n(l)){if(b.isEqual(i)){return}}try{i.select()}catch(c){}b=this.createRange(this.getSelection());if(b.parentElement){l=b.parentElement()}else{l=b.item(0)}if(l!=f){var d=this.config.selectWorkaround||"VisibleCue";switch(d){case"SimulateClick":case"InsertSpan":var h=n(f);var j=function(p){var o="";for(var e=0;e<26;++e){o+=String.fromCharCode("a".charCodeAt(0)+e)}var q="";for(var e=0;e<p;++e){q+=o.substr(Math.floor(Math.random()*o.length+1),1)}return q};var m=1;var g="__InsertSpan_Workaround_"+j(m);while(h.getElementById(g)){m+=1;g="__InsertSpan_Workaround_"+j(m)}i.pasteHTML(\'<span id="\'+g+\'"></span>\');var k=h.getElementById(g);i.moveToElementText(k);i.select();break;case"JustificationHack":var a=String.fromCharCode(1);i.pasteHTML(a);i.findText(a,-1);i.select();i.execCommand("JustifyNone");i.pasteHTML("");break;case"VisibleCue":default:var a=String.fromCharCode(1);i.pasteHTML(a);i.findText(a,-1);i.select()}}};Xinha.prototype.selectNodeContents=function(e,a){this.focusEditor();this.forceRedraw();var b;var g=typeof a=="undefined"?true:false;if(g&&e.tagName&&e.tagName.toLowerCase().match(/table|img|input|select|textarea/)){b=this._doc.body.createControlRange();b.add(e)}else{b=this._doc.body.createTextRange();if(3==e.nodeType){if(e.parentNode){b.moveToElementText(e.parentNode)}else{b.moveToElementText(this._doc.body)}var f=this._doc.body.createTextRange();var d=0;var c=e.previousSibling;for(;c&&(1!=c.nodeType);c=c.previousSibling){if(3==c.nodeType){d+=c.nodeValue.length-c.nodeValue.split("\\r").length-1}}if(c&&(1==c.nodeType)){f.moveToElementText(c);b.setEndPoint("StartToEnd",f)}if(d){b.moveStart("character",d)}d=0;c=e.nextSibling;for(;c&&(1!=c.nodeType);c=c.nextSibling){if(3==c.nodeType){d+=c.nodeValue.length-c.nodeValue.split("\\r").length-1;if(!c.nextSibling){d+=1}}}if(c&&(1==c.nodeType)){f.moveToElementText(c);b.setEndPoint("EndToStart",f)}if(d){b.moveEnd("character",-d)}if(!e.nextSibling){b.moveEnd("character",-1)}}else{b.moveToElementText(e)}}if(typeof a!="undefined"){b.collapse(a);if(!a){b.moveStart("character",-1);b.moveEnd("character",-1)}}b.select()};Xinha.prototype.insertHTML=function(b){this.focusEditor();var c=this.getSelection();var a=this.createRange(c);a.pasteHTML(b)};Xinha.prototype.getSelectedHTML=function(){var b=this.getSelection();if(this.selectionEmpty(b)){return""}var a=this.createRange(b);if(a.htmlText){return a.htmlText}else{if(a.length>=1){return a.item(0).outerHTML}}return""};Xinha.prototype.getSelection=function(){return this._doc.selection};Xinha.prototype.createRange=function(a){if(!a){a=this.getSelection()}return a.createRange()};Xinha.prototype.isKeyEvent=function(a){return a.type=="keydown"};Xinha.prototype.getKey=function(a){return String.fromCharCode(a.keyCode)};Xinha.getOuterHTML=function(a){return a.outerHTML};Xinha.cc=String.fromCharCode(8201);Xinha.prototype.setCC=function(d){var f=Xinha.cc;if(d=="textarea"){var h=this._textArea;var j=document.selection.createRange();j.collapse();j.text=f;var i=h.value.indexOf(f);var k=h.value.substring(0,i);var c=h.value.substring(i+f.length,h.value.length);if(c.match(/^[^<]*>/)){var b=c.indexOf(">")+1;h.value=k+c.substring(0,b)+f+c.substring(b,c.length)}else{h.value=k+f+c}h.value=h.value.replace(new RegExp("(&[^"+f+"]*?)("+f+")([^"+f+"]*?;)"),"$1$3$2");h.value=h.value.replace(new RegExp("(<script[^>]*>[^"+f+"]*?)("+f+")([^"+f+"]*?<\\/script>)"),"$1$3$2");h.value=h.value.replace(new RegExp("^([^"+f+"]*)("+f+")([^"+f+"]*<body[^>]*>)(.*?)"),"$1$3$2$4")}else{var e=this.getSelection();var a=e.createRange();if(e.type=="Control"){var g=a.item(0);g.outerHTML+=f}else{a.collapse();a.text=f}}};Xinha.prototype.findCC=function(b){var a=(b=="textarea")?this._textArea:this._doc.body;range=a.createTextRange();if(range.findText(escape(Xinha.cc))){range.select();range.text="";range.select()}if(range.findText(Xinha.cc)){range.select();range.text="";range.select()}if(b=="textarea"){this._textArea.focus()}};Xinha.getDoctype=function(a){return(a.compatMode=="CSS1Compat"&&Xinha.ie_version<8)?\'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\':""};

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>9527</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>InternetExplorer.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
