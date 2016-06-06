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
            <value> <string>ts68192110.7</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ERP5VCS_menuico.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

  function CreateToolBarMenu(colBackground, colLight, colShadow, colFlash, style, height, width) {\n
    this.nb=0;\n
    this.colBackground=colBackground;\n
    this.colLight=colLight;\n
    this.colShadow=colShadow;\n
    this.colFlash=colFlash;\n
    this.height=height;\n
    this.width=width;\n
    this.style=style;\n
    this.Index=-1;\n
    this.NbFlash=0;\n
    this.Add=AddMenuToolBar;\n
    this.Display=DisplayToolBarMenu;\n
  }\n
  \n
  function AddMenuToolBar(imgOff, imgOn, text, url, js) {\n
    var link=new Object();\n
    link.imgOff=imgOff;\n
    link.imgOn=imgOn;\n
    link.text=text;\n
    link.url=url;\n
    link.js=js;\n
    this[this.nb]=link;\n
    this.nb++;\n
  }\n
  \n
  function DisplayToolBarMenu() {\n
          var Z;\n
          var i=0;\n
          if (document.getElementById || document.all) {\n
                  Z="<div style=\'text:align: center;\'><table cellpadding=\'1\' cellspacing=\'1\' style=\'border:0;margin-left:auto; margin-right:auto;\'><tr>";\n
                  for (i=0; i<this.nb; i++) {\n
                          Z+="<td onMouseOver=\'DisplayToolBarMenuOver(this,"+i+")\' onMouseOut=\'DisplayToolBarMenuOut(this,"+i+")\' onMouseDown=\'DisplayToolBarMenuDown(this,"+i+")\' onClick=\'DisplayToolBarMenuClick(this,"+i+")\' style=\'border-style:solid;border-width:1px;border-color:"+this.colBackground+";"+this.style+";cursor:pointer\'><img name=\'MenuToolBarIMG"+i+"\' src=\'"+this[i].imgOff+"\' border=0 width="+this.width+" height="+this.height+" align=top>&nbsp;"+this[i].text+"</TD>";\n
                  }\n
                  Z+="</tr></table></div";\n
          } else {\n
                  Z="| &nbsp;";\n
                  for (i=0; i<this.nb; i++) {\n
                          Z+="<a href=\'"+this[i].url+"\' style=\'"+this.style+"\'><img name=\'MenuToolBarIMG"+i+"\' src=\\""+this[i].imgOff+"\\" border=0 width="+this.width+" height="+this.height+" align=top>&nbsp;"+this[i].text+"</a>&nbsp;|&nbsp;";\n
                  }\n
          }\n
          document.write(Z);\n
  }\n
  function DisplayToolBarMenuOver(obj,ind) {\n
    obj.style.borderTopColor=MenuToolBar.colLight;\t\n
    obj.style.borderLeftColor=MenuToolBar.colLight;\t\n
    obj.style.borderBottomColor=MenuToolBar.colShadow;\t\n
    obj.style.borderRightColor=MenuToolBar.colShadow;\t\n
    document.images[\'MenuToolBarIMG\'+ind].src=MenuToolBar[ind].imgOn;\n
  }\n
  \n
  function DisplayToolBarMenuOut(obj,ind) {\n
    obj.style.borderTopColor=MenuToolBar.colBackground;\t\n
    obj.style.borderBottomColor=MenuToolBar.colBackground;\t\n
    obj.style.borderLeftColor=MenuToolBar.colBackground;\t\n
    obj.style.borderRightColor=MenuToolBar.colBackground;\t\n
    document.images[\'MenuToolBarIMG\'+ind].src=MenuToolBar[ind].imgOff;\n
  }\n
  \n
  \n
  function DisplayToolBarMenuDown(obj,ind) {\n
    obj.style.borderTopColor=MenuToolBar.colShadow;\n
    obj.style.borderLeftColor=MenuToolBar.colShadow;\t\n
    obj.style.borderBottomColor=MenuToolBar.colLight;\t\n
    obj.style.borderRightColor=MenuToolBar.colLight;\n
  }\n
  \n
  function DisplayToolBarMenuClick(obj,ind) {\n
    MenuToolBar.Index=ind;\n
    MenuToolBar.obj=obj;\n
    MenuToolBar.NbFlash=0;\n
    MenuToolBarFlash();\n
  }\n
  \n
  function MenuToolBarFlash() {\n
          MenuToolBar.NbFlash++;\n
          if (Math.round(MenuToolBar.NbFlash/2) != MenuToolBar.NbFlash/2) {\n
                  MenuToolBar.obj.style.backgroundColor=MenuToolBar.colFlash;\n
          } else {\n
                  MenuToolBar.obj.style.backgroundColor=MenuToolBar.colBackground;\n
          }\n
          if (MenuToolBar.NbFlash < 8) {\n
                  setTimeout(\'MenuToolBarFlash()\',50-5*MenuToolBar.NbFlash);\n
          } else {\n
                  eval(MenuToolBar[MenuToolBar.Index].js);\n
                  //window.location=MenuToolBar[MenuToolBar.Index].url;\n
          }\n
  }\n
  \n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>3668</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
