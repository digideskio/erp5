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
            <value> <string>ts86919745.46</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>full-screen.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/* This compressed file is part of Xinha. For uncompressed sources, forum, and bug reports, go to xinha.org */\n
function FullScreen(b,c){this.editor=b;this.originalSizes=null;b._superclean_on=false;var a=b.config;a.registerIcon("fullscreen",[_editor_url+a.imgURL+"ed_buttons_main.png",8,0]);a.registerIcon("fullscreenrestore",[_editor_url+a.imgURL+"ed_buttons_main.png",9,0]);a.registerButton("fullscreen",this._lc("Maximize/Minimize Editor"),a.iconList.fullscreen,true,function(g,f,d){g._fullScreen()});a.addToolbarElement("fullscreen","popupeditor",0)}FullScreen._pluginInfo={name:"FullScreen",version:"1.0",developer:"James Sleeman",developer_url:"http://www.gogo.co.nz/",c_owner:"Gogo Internet Services",license:"htmlArea",sponsor:"Gogo Internet Services",sponsor_url:"http://www.gogo.co.nz/"};FullScreen.prototype._lc=function(a){return Xinha._lc(a,{url:_editor_url+"modules/FullScreen/lang/",context:"FullScreen"})};Xinha.prototype._fullScreen=function(){var g=this;var d=g.config;function j(){if(!g._isFullScreen||g._sizing){return false}g._sizing=true;var n=Xinha.viewportSize();if(g.config.fullScreenSizeDownMethod=="restore"){g.originalSizes={x:parseInt(g._htmlArea.style.width),y:parseInt(g._htmlArea.style.height),dim:n}}var i=n.y-g.config.fullScreenMargins[0]-g.config.fullScreenMargins[2];var e=n.x-g.config.fullScreenMargins[1]-g.config.fullScreenMargins[3];g.sizeEditor(e+"px",i+"px",true,true);g._sizing=false;if(g._toolbarObjects.fullscreen){g._toolbarObjects.fullscreen.swapImage(d.iconList.fullscreenrestore)}}function l(){if(g._isFullScreen||g._sizing){return false}g._sizing=true;if(g.originalSizes!=null){var o=g.originalSizes;var n=Xinha.viewportSize();var e=o.x+(n.x-o.dim.x);var i=o.y+(n.y-o.dim.y);g.sizeEditor(e+"px",i+"px",g.config.sizeIncludesBars,g.config.sizeIncludesPanels);g.originalSizes=null}else{g.initSize()}g._sizing=false;if(g._toolbarObjects.fullscreen){g._toolbarObjects.fullscreen.swapImage(d.iconList.fullscreen)}}function f(){if(g._isFullScreen){window.scroll(0,0);window.setTimeout(f,150)}}if(typeof this._isFullScreen=="undefined"){this._isFullScreen=false;if(g.target!=g._iframe){Xinha._addEvent(window,"resize",j)}}if(Xinha.is_gecko){this.deactivateEditor()}if(this._isFullScreen){this._htmlArea.style.position="";if(!Xinha.is_ie){this._htmlArea.style.border=""}try{if(Xinha.is_ie&&document.compatMode=="CSS1Compat"){var b=document.getElementsByTagName("html")}else{var b=document.getElementsByTagName("body")}b[0].style.overflow=""}catch(g){}this._isFullScreen=false;l();var a=this._htmlArea;while((a=a.parentNode)&&a.style){a.style.position=a._xinha_fullScreenOldPosition;a._xinha_fullScreenOldPosition=null}if(Xinha.ie_version<7){var h=document.getElementsByTagName("select");for(var c=0;c<h.length;++c){h[c].style.visibility="visible"}}window.scroll(this._unScroll.x,this._unScroll.y)}else{this._unScroll={x:(window.pageXOffset)?(window.pageXOffset):(document.documentElement)?document.documentElement.scrollLeft:document.body.scrollLeft,y:(window.pageYOffset)?(window.pageYOffset):(document.documentElement)?document.documentElement.scrollTop:document.body.scrollTop};var a=this._htmlArea;while((a=a.parentNode)&&a.style){a._xinha_fullScreenOldPosition=a.style.position;a.style.position="static"}if(Xinha.ie_version<7){var h=document.getElementsByTagName("select");var m,k;for(var c=0;c<h.length;++c){m=h[c];k=false;while(m=m.parentNode){if(m==this._htmlArea){k=true;break}}if(!k&&h[c].style.visibility!="hidden"){h[c].style.visibility="hidden"}}}window.scroll(0,0);this._htmlArea.style.position="absolute";this._htmlArea.style.zIndex=999;this._htmlArea.style.left=g.config.fullScreenMargins[3]+"px";this._htmlArea.style.top=g.config.fullScreenMargins[0]+"px";if(!Xinha.is_ie&&!Xinha.is_webkit){this._htmlArea.style.border="none"}this._isFullScreen=true;f();try{if(Xinha.is_ie&&document.compatMode=="CSS1Compat"){var b=document.getElementsByTagName("html")}else{var b=document.getElementsByTagName("body")}b[0].style.overflow="hidden"}catch(g){}j()}if(Xinha.is_gecko){this.activateEditor()}this.focusEditor()};

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>4063</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>full-screen.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
