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
            <value> <string>ts86919621.75</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>dialog.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/* This compressed file is part of Xinha. For uncompressed sources, forum, and bug reports, go to xinha.org */\n
function Dialog(b,a,d){if(typeof d=="undefined"){d=window}if(typeof window.showModalDialog=="function"&&!Xinha.is_webkit){Dialog._return=function(e){if(typeof a=="function"){a(e)}};var c=window.showModalDialog(b,d,"dialogheight=300;dialogwidth=400;resizable=yes")}else{Dialog._geckoOpenModal(b,a,d)}}Dialog._parentEvent=function(a){setTimeout(function(){if(Dialog._modal&&!Dialog._modal.closed){Dialog._modal.focus()}},50);try{if(Dialog._modal&&!Dialog._modal.closed){Xinha._stopEvent(a)}}catch(b){}};Dialog._return=null;Dialog._modal=null;Dialog._arguments=null;Dialog._selection=null;Dialog._geckoOpenModal=function(b,a,j){var h=window.open(b,"hadialog","toolbar=no,menubar=no,personalbar=no,width=10,height=10,scrollbars=no,resizable=yes,modal=yes,dependable=yes");Dialog._modal=h;Dialog._arguments=j;function d(e){Xinha._addEvent(e,"click",Dialog._parentEvent);Xinha._addEvent(e,"mousedown",Dialog._parentEvent);Xinha._addEvent(e,"focus",Dialog._parentEvent)}function f(e){Xinha._removeEvent(e,"click",Dialog._parentEvent);Xinha._removeEvent(e,"mousedown",Dialog._parentEvent);Xinha._removeEvent(e,"focus",Dialog._parentEvent)}d(window);for(var c=0;c<window.frames.length;c++){try{d(window.frames[c])}catch(g){}}Dialog._return=function(m){if(m&&a){a(m)}f(window);for(var k=0;k<window.frames.length;k++){try{f(window.frames[k])}catch(l){}}Dialog._modal=null};Dialog._modal.focus()};

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>1496</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>dialog.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
