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
            <value> <string>ts68190334.01</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ERP5VCS_dhtmlXTree.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

function dhtmlXTreeObject(htmlObject,width,height,rootId){\n
 if(typeof(htmlObject)!="object")\n
 this.parentObject=document.getElementById(htmlObject);\n
 else\n
 this.parentObject=htmlObject;\n
\n
 this.xmlstate=0;\n
 this.mytype="tree";\n
 this.smcheck=true;\n
 this.width=width;\n
 this.height=height;\n
 this.rootId=rootId;\n
 this.childCalc=null;\n
 this.def_img_x="22px";\n
 this.def_img_y="22px";\n
\n
 this.style_pointer="pointer";\n
 if(navigator.appName == \'Microsoft Internet Explorer\')this.style_pointer="hand";\n
 \n
 this._aimgs=true;\n
 this.htmlcA=" [";\n
 this.htmlcB="]";\n
 this.lWin=window;\n
 this.cMenu=0;\n
 this.mlitems=0;\n
 this.dadmode=0;\n
 this.slowParse=false;\n
 this.autoScroll=true;\n
 this.hfMode=0;\n
 this.nodeCut=0;\n
 this.XMLsource=0;\n
 this.XMLloadingWarning=0;\n
 this._globalIdStorage=new Array();\n
 this.globalNodeStorage=new Array();\n
 this._globalIdStorageSize=0;\n
 this.treeLinesOn=true;\n
 this.checkFuncHandler=0;\n
 this.openFuncHandler=0;\n
 this.dblclickFuncHandler=0;\n
 this.tscheck=false;\n
 this.timgen=true;\n
\n
 this.dpcpy=false;\n
 \n
 this.imPath="treeGfx/";\n
 this.checkArray=new Array("iconUnCheckAll.gif","iconCheckAll.gif","iconCheckGray.gif","iconUncheckDis.gif");\n
 this.lineArray=new Array("line2.gif","line3.gif","line4.gif","blank.gif","blank.gif");\n
 this.minusArray=new Array("minus2.gif","minus3.gif","minus4.gif","minus.gif","minus5.gif");\n
 this.plusArray=new Array("plus2.gif","plus3.gif","plus4.gif","plus.gif","plus5.gif");\n
 this.imageArray=new Array("document.png","folder_open.png","folder.png");\n
 this.cutImg= new Array(0,0,0);\n
 this.cutImage="but_cut.gif";\n
 \n
 this.dragger= new dhtmlDragAndDropObject();\n
 \n
 this.htmlNode=new dhtmlXTreeItemObject(this.rootId,"",0,this);\n
 this.htmlNode.htmlNode.childNodes[0].childNodes[0].style.display="none";\n
 this.htmlNode.htmlNode.childNodes[0].childNodes[0].childNodes[0].className="hiddenRow";\n
 \n
 this.allTree=this._createSelf();\n
 this.allTree.appendChild(this.htmlNode.htmlNode);\n
 this.allTree.onselectstart=new Function("return false;");\n
 this.XMLLoader=new dtmlXMLLoaderObject(this._parseXMLTree,this);\n
 \n
 this.selectionBar=document.createElement("DIV");\n
 this.selectionBar.className="selectionBar";\n
 this.selectionBar.innerHTML="&nbsp;";\n
 \n
 if(this.allTree.offsetWidth>20)this.selectionBar.style.width=this.allTree.offsetWidth-20;\n
 this.selectionBar.style.display="none";\n
 \n
 this.allTree.appendChild(this.selectionBar);\n
 \n
 \n
 \n
\n
 return this;\n
}\n
\n
 \n
function dhtmlXTreeItemObject(itemId,itemText,parentObject,treeObject,actionHandler,mode){\n
 this.htmlNode="";\n
 this.acolor="";\n
 this.scolor="";\n
 this.tr=0;\n
 this.childsCount=0;\n
 this.tempDOMM=0;\n
 this.tempDOMU=0;\n
 this.dragSpan=0;\n
 this.dragMove=0;\n
 this.span=0;\n
 this.closeble=1;\n
 this.childNodes=new Array();\n
 this.userData=new Object();\n
 \n
 this.checkstate=0;\n
 this.treeNod=treeObject;\n
 this.label=itemText;\n
 this.parentObject=parentObject;\n
 this.actionHandler=actionHandler;\n
 this.images=new Array(treeObject.imageArray[0],treeObject.imageArray[1],treeObject.imageArray[2]);\n
\n
\n
 this.id=treeObject._globalIdStorageAdd(itemId,this);\n
 if(this.treeNod.checkBoxOff)this.htmlNode=this.treeNod._createItem(1,this,mode);\n
 else this.htmlNode=this.treeNod._createItem(0,this,mode);\n
 \n
 this.htmlNode.objBelong=this;\n
 return this;\n
}\n
\n
 dhtmlXTreeObject.prototype._getAllParentId=function(temp, list_id)\n
{\n
 if(!temp || !temp.parentObject || temp.parentObject.id===0) return list_id;\n
 return this._getAllParentId(temp.parentObject, list_id+\',\'+temp.parentObject.id);\n
}; \n
\n
 dhtmlXTreeObject.prototype.getAllParentId=function(itemId)\n
{\n
 var temp=this._globalIdStorageFind(itemId);\n
 if((!temp)||(!temp.parentObject)||temp.parentObject.id===0){\n
   return "";\n
 }else{\n
   list_id = this._getAllParentId(temp.parentObject, temp.parentObject.id);\n
   return list_id.substring(0, list_id.length);\n
 }\n
};\n
  \n
 dhtmlXTreeObject.prototype._globalIdStorageAdd=function(itemId,itemObject){\n
 if(this._globalIdStorageFind(itemId,1,1)){d=new Date();itemId=d.valueOf()+"_"+itemId;return this._globalIdStorageAdd(itemId,itemObject);}\n
 this._globalIdStorage[this._globalIdStorageSize]=itemId;\n
 this.globalNodeStorage[this._globalIdStorageSize]=itemObject;\n
 this._globalIdStorageSize++;\n
 return itemId;\n
};\n
 \n
 dhtmlXTreeObject.prototype._globalIdStorageSub=function(itemId){\n
 for(var i=0;i<this._globalIdStorageSize;i++){\n
 if(this._globalIdStorage[i]==itemId)\n
{\n
 this._globalIdStorage[i]=this._globalIdStorage[this._globalIdStorageSize-1];\n
 this.globalNodeStorage[i]=this.globalNodeStorage[this._globalIdStorageSize-1];\n
 this._globalIdStorageSize--;\n
 this._globalIdStorage[this._globalIdStorageSize]=0;\n
 this.globalNodeStorage[this._globalIdStorageSize]=0;\n
}\n
}\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype._globalIdStorageFind=function(itemId,skipXMLSearch,skipParsing){\n
 \n
 for(var i=0;i<this._globalIdStorageSize;i++){\n
 if(this._globalIdStorage[i]==itemId)\n
{\n
 return this.globalNodeStorage[i];\n
}\n
}\n
 \n
 return null;\n
};\n
\n
\n
\n
\n
\n
\n
 \n
 \n
 dhtmlXTreeObject.prototype._drawNewTr=function(htmlObject,node)\n
{\n
 var tr =document.createElement(\'tr\');\n
 var td1=document.createElement(\'td\');\n
 var td2=document.createElement(\'td\');\n
 td1.appendChild(document.createTextNode(" "));\n
 td2.colSpan=3;\n
 td2.appendChild(htmlObject);\n
 tr.appendChild(td1);tr.appendChild(td2);\n
 return tr;\n
};\n
 \n
 dhtmlXTreeObject.prototype.loadXMLString=function(xmlString,afterCall){\n
 this.xmlstate=1;\n
 this.XMLLoader.loadXMLString(xmlString);this.waitCall=afterCall||0;};\n
 \n
 dhtmlXTreeObject.prototype.loadXML=function(file,afterCall){\n
 this.xmlstate=1;\n
 this.XMLLoader.loadXML(file);this.waitCall=afterCall||0;\n
 };\n
 \n
 dhtmlXTreeObject.prototype._attachChildNode=function(parentObject,itemId,itemText,itemActionHandler,image1,image2,image3,optionStr,childs,beforeNode){\n
 if(beforeNode)parentObject=beforeNode.parentObject;\n
 if(((parentObject.XMLload===0)&&(this.XMLsource))&&(!this.XMLloadingWarning))\n
{\n
 parentObject.XMLload=1;this.loadXML(this.XMLsource+getUrlSymbol(this.XMLsource)+"itemId="+escape(parentObject.id));\n
}\n
 \n
 var Count=parentObject.childsCount;\n
 var Nodes=parentObject.childNodes;\n
\n
 if(beforeNode)\n
{\n
 var ik,jk;\n
 for(ik=0;ik<Count;ik++){\n
 if(Nodes[ik]==beforeNode)\n
{\n
 for(jk=Count;jk!=ik;jk--)\n
 Nodes[1+jk]=Nodes[jk];\n
 break;\n
}\n
}\n
 ik++;\n
 Count=ik;\n
}\n
 \n
 if((!itemActionHandler)&&(this.aFunc))itemActionHandler=this.aFunc;\n
 \n
 if(optionStr){\n
 var tempStr=optionStr.split(",");\n
 for(var i=0;i<tempStr.length;i++)\n
{\n
 switch(tempStr[i])\n
{\n
 case "TOP": if(parentObject.childsCount>0){beforeNode=new Object;beforeNode.tr=parentObject.childNodes[0].tr.previousSibling;}\n
 for(ik=0;ik<Count;ik++)\n
 Nodes[ik+Count]=Nodes[ik+Count-1];\n
 Count=0;\n
 break;\n
 default: break;\n
}\n
}\n
}\n
\n
 Nodes[Count]=new dhtmlXTreeItemObject(itemId,itemText,parentObject,this,itemActionHandler,1);\n
\n
 if(image1)Nodes[Count].images[0]=image1;\n
 if(image2)Nodes[Count].images[1]=image2;\n
 if(image3)Nodes[Count].images[2]=image3;\n
 \n
 parentObject.childsCount++;\n
 var tr=this._drawNewTr(Nodes[Count].htmlNode);\n
 if(this.XMLloadingWarning)\n
 Nodes[Count].htmlNode.parentNode.parentNode.style.display="none";\n
 \n
\n
 \n
 if((beforeNode)&&(beforeNode.tr.nextSibling))\n
 parentObject.htmlNode.childNodes[0].insertBefore(tr,beforeNode.tr.nextSibling);\n
 else\n
 if((this.parsingOn)&&(this.parsingOn==parentObject.id))\n
{\n
 this.parsedArray[this.parsedArray.length]=tr;\n
}\n
 else \n
 parentObject.htmlNode.childNodes[0].appendChild(tr);\n
\n
 if((beforeNode)&&(!beforeNode.span))beforeNode=null;\n
 \n
 if(this.XMLsource){if((childs)&&(childs!==0))Nodes[Count].XMLload=0;else Nodes[Count].XMLload=1;}\n
\n
 Nodes[Count].tr=tr;\n
 tr.nodem=Nodes[Count];\n
\n
 if(parentObject.itemId===0)\n
 tr.childNodes[0].className="hitemIddenRow";\n
 \n
 if(optionStr){\n
   tempStr=optionStr.split(",");\n
 \n
 for(i=0;i<tempStr.length;i++)\n
{\n
 switch(tempStr[i])\n
{\n
 case "SELECT": this.selectItem(itemId,false);break;\n
 case "CALL": this.selectItem(itemId,true);break;\n
 case "CHILD": Nodes[Count].XMLload=0;break;\n
 case "CHECKED": \n
 if(this.XMLloadingWarning)\n
 this.setCheckList+=","+itemId;\n
 else\n
 this.setCheck(itemId,1);\n
 break;\n
 case "HCHECKED":\n
 this._setCheck(Nodes[Count],"notsure");\n
 break;\n
 case "OPEN": Nodes[Count].openMe=1;break;\n
 default: break;\n
}\n
}\n
}\n
\n
 if(!this.XMLloadingWarning)\n
{\n
 if(this._getOpenState(parentObject)<0)\n
 this.openItem(parentObject.id);\n
 \n
 if(beforeNode)\n
{\n
 this._correctPlus(beforeNode);\n
 this._correctLine(beforeNode);\n
}\n
 this._correctPlus(parentObject);\n
 this._correctLine(parentObject);\n
 this._correctPlus(Nodes[Count]);\n
 if(parentObject.childsCount>=2)\n
{\n
 this._correctPlus(Nodes[parentObject.childsCount-2]);\n
 this._correctLine(Nodes[parentObject.childsCount-2]);\n
}\n
 if(parentObject.childsCount!=2)this._correctPlus(Nodes[0]);\n
 if(this.tscheck)this._correctCheckStates(parentObject);\n
}\n
\n
 if(this.cMenu)this.cMenu.setContextZone(Nodes[Count].span,Nodes[Count].id);\n
 return Nodes[Count];\n
};\n
\n
\n
 \n
 dhtmlXTreeObject.prototype.insertNewItem=function(parentId,itemId,itemText,itemActionHandler,image1,image2,image3,optionStr,childs){\n
 var parentObject=this._globalIdStorageFind(parentId);\n
 if(!parentObject)return(-1);\n
 return this._attachChildNode(parentObject,itemId,itemText,itemActionHandler,image1,image2,image3,optionStr,childs);\n
};\n
 \n
 dhtmlXTreeObject.prototype._parseXMLTree=function(dhtmlObject,node,parentId,level){\n
\n
 \n
 if(!dhtmlObject.parsCount)dhtmlObject.parsCount=1;else dhtmlObject.parsCount++;\n
 \n
 dhtmlObject.XMLloadingWarning=1;\n
 var nodeAskingCall="";\n
 if(!node){\n
 node=dhtmlObject.XMLLoader.getXMLTopNode("tree");\n
 parentId=node.getAttribute("id");\n
 dhtmlObject.parsingOn=parentId;\n
 dhtmlObject.parsedArray=new Array();\n
 dhtmlObject.setCheckList="";\n
}\n
\n
\n
 if(node.getAttribute("order"))\n
 dhtmlObject._reorderXMLBranch(node);\n
\n
\n
 for(var i=0;i<node.childNodes.length;i++)\n
{\n
 if((node.childNodes[i].nodeType==1)&&(node.childNodes[i].tagName == "item"))\n
{\n
 var nodx=node.childNodes[i];\n
 var name=nodx.getAttribute("text");\n
 var cId=nodx.getAttribute("id");\n
 if((!dhtmlObject.waitUpdateXML)||(dhtmlObject.waitUpdateXML.toString().search(","+cId+",")!=-1))\n
{\n
 var im0=nodx.getAttribute("im0");\n
 var im1=nodx.getAttribute("im1");\n
 var im2=nodx.getAttribute("im2");\n
 \n
 var aColor=nodx.getAttribute("aCol");\n
 //var sColor=nodx.getAttribute("sCol");\n
 var sColor=aColor;\n
 \n
 var chd=nodx.getAttribute("child");\n
\n
 \n
 var atop=nodx.getAttribute("top");\n
 var aopen=nodx.getAttribute("open");\n
 var aselect=nodx.getAttribute("select");\n
 var acall=nodx.getAttribute("call");\n
 var achecked=nodx.getAttribute("checked");\n
 var closeable=nodx.getAttribute("closeable");\n
 var tooltip = nodx.getAttribute("tooltip");\n
 var nocheckbox = nodx.getAttribute("nocheckbox");\n
 var style = nodx.getAttribute("style");\n
 \n
 var zST="";\n
 if(aselect)zST+=",SELECT";\n
 if(atop)zST+=",TOP";\n
 \n
 if(acall)nodeAskingCall=cId;\n
 if(achecked==-1)zST+=",HCHECKED";\n
 else if(achecked)zST+=",CHECKED";\n
 if(aopen)zST+=",OPEN";\n
 \n
 var temp=dhtmlObject._globalIdStorageFind(parentId);\n
 temp.XMLload=1;\n
 var newNode=dhtmlObject.insertNewItem(parentId,cId,name,0,im0,im1,im2,zST,chd);\n
\n
 if(tooltip)newNode.span.parentNode.title=tooltip;\n
 if(style)newNode.span.style.cssText+=(";"+style);\n
 if(nocheckbox){\n
 newNode.span.parentNode.previousSibling.previousSibling.childNodes[0].style.display=\'none\';\n
 newNode.nocheckbox=true;\n
}\n
 \n
 newNode._acc=chd||0;\n
 \n
\n
 if(dhtmlObject.parserExtension)dhtmlObject.parserExtension._parseExtension(node.childNodes[i],dhtmlObject.parserExtension,cId,parentId);\n
 \n
 dhtmlObject.setItemColor(newNode,aColor,sColor);\n
\n
 if((closeable=="0")||(closeable=="1"))dhtmlObject.setItemCloseable(newNode,closeable);\n
 var zcall="";\n
 if((!dhtmlObject.slowParse)||(dhtmlObject.waitUpdateXML))\n
{\n
 zcall=dhtmlObject._parseXMLTree(dhtmlObject,node.childNodes[i],cId,1);\n
}\n
 else{\n
 if(node.childNodes[i].childNodes.length>0){\n
 for(var a=0;a<node.childNodes[i].childNodes.length;a++){\n
 if(node.childNodes[i].childNodes[a].tagName=="item"){\n
 newNode.unParsed=node.childNodes[i];\n
 break;\n
}\n
}\n
}\n
}\n
 \n
 if(zcall!=="")nodeAskingCall=zcall;\n
 \n
}\n
 else dhtmlObject._parseXMLTree(dhtmlObject,node.childNodes[i],cId,1);\n
}\n
 else\n
 if((node.childNodes[i].nodeType==1)&&(node.childNodes[i].tagName == "userdata"))\n
{\n
 name=node.childNodes[i].getAttribute("name");\n
 if((name)&&(node.childNodes[i].childNodes[0])){\n
 if((!dhtmlObject.waitUpdateXML)||(dhtmlObject.waitUpdateXML.toString().search(","+parentId+",")!=-1))\n
 dhtmlObject.setUserData(parentId,name,node.childNodes[i].childNodes[0].data);\n
}\n
}\n
}\n
\n
 if(!level){\n
 if(dhtmlObject.waitUpdateXML)\n
 dhtmlObject.waitUpdateXML="";\n
 else{\n
 \n
 var parsedNodeTop=dhtmlObject._globalIdStorageFind(dhtmlObject.parsingOn);\n
 for(i=0;i<dhtmlObject.parsedArray.length;i++)\n
 parsedNodeTop.htmlNode.childNodes[0].appendChild(dhtmlObject.parsedArray[i]);\n
 dhtmlObject.parsingOn=0;\n
\n
 dhtmlObject.lastLoadedXMLId=parentId;\n
\n
 dhtmlObject.XMLloadingWarning=0;\n
 var chArr=dhtmlObject.setCheckList.split(",");\n
 for(var n=0;n<chArr.length;n++){\n
 if(chArr[n])dhtmlObject.setCheck(chArr[n],1);\n
 }\n
 dhtmlObject._redrawFrom(dhtmlObject);\n
\n
 if(nodeAskingCall!=="")dhtmlObject.selectItem(nodeAskingCall,true);\n
 if(dhtmlObject.waitCall)dhtmlObject.waitCall();\n
}\n
}\n
 \n
\n
 if(dhtmlObject.parsCount==1){\n
 dhtmlObject.xmlstate=1;\n
}\n
 dhtmlObject.parsCount--;\n
\n
 return nodeAskingCall;\n
};\n
\n
\n
 \n
\n
\n
 \n
 dhtmlXTreeObject.prototype._redrawFrom=function(dhtmlObject,itemObject){\n
 if(!itemObject){\n
 var tempx=dhtmlObject._globalIdStorageFind(dhtmlObject.lastLoadedXMLId);\n
 dhtmlObject.lastLoadedXMLId=-1;\n
 if(!tempx)return 0;\n
}\n
 else tempx=itemObject;\n
 var acc=0;\n
 \n
 for(var i=0;i<tempx.childsCount;i++)\n
{\n
 if(!itemObject)tempx.childNodes[i].htmlNode.parentNode.parentNode.style.display="";\n
 if(tempx.childNodes[i].openMe==1)\n
{\n
 this._openItem(tempx.childNodes[i]);\n
 tempx.childNodes[i].openMe=0;\n
}\n
 \n
 dhtmlObject._redrawFrom(dhtmlObject,tempx.childNodes[i]);\n
 \n
 if(this.childCalc!==null){\n
 \n
 if((tempx.childNodes[i].unParsed)||((!tempx.childNodes[i].XMLload)&&(this.XMLsource)))\n
{\n
\n
 if(tempx.childNodes[i]._acc)\n
 tempx.childNodes[i].span.innerHTML=tempx.childNodes[i].label+this.htmlcA+tempx.childNodes[i]._acc+this.htmlcB;\n
 else \n
 tempx.childNodes[i].span.innerHTML=tempx.childNodes[i].label;\n
}\n
 \n
 if((tempx.childNodes[i].childNodes.length)&&(this.childCalc))\n
{\n
 if(this.childCalc==1)\n
{\n
 tempx.childNodes[i].span.innerHTML=tempx.childNodes[i].label+this.htmlcA+tempx.childNodes[i].childsCount+this.htmlcB;\n
}\n
 if(this.childCalc==2)\n
{\n
 var zCount=tempx.childNodes[i].childsCount-(tempx.childNodes[i].pureChilds||0);\n
 if(zCount)\n
 tempx.childNodes[i].span.innerHTML=tempx.childNodes[i].label+this.htmlcA+zCount+this.htmlcB;\n
 if(tempx.pureChilds)tempx.pureChilds++;else tempx.pureChilds=1;\n
}\n
 if(this.childCalc==3)\n
{\n
 tempx.childNodes[i].span.innerHTML=tempx.childNodes[i].label+this.htmlcA+tempx.childNodes[i]._acc+this.htmlcB;\n
}\n
 if(this.childCalc==4)\n
{\n
 zCount=tempx.childNodes[i]._acc;\n
 if(zCount)\n
 tempx.childNodes[i].span.innerHTML=tempx.childNodes[i].label+this.htmlcA+zCount+this.htmlcB;\n
}\n
}\n
 else if(this.childCalc==4){\n
 acc++;\n
}\n
 \n
 acc+=tempx.childNodes[i]._acc;\n
 \n
 if(this.childCalc==3){\n
 acc++;\n
}\n
 \n
}\n
 \n
 \n
 \n
}\n
 \n
 if((!tempx.unParsed)&&((tempx.XMLload)||(!this.XMLsource)))\n
 tempx._acc=acc;\n
 dhtmlObject._correctLine(tempx);\n
 dhtmlObject._correctPlus(tempx);\n
 return "";\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype._createSelf=function(){\n
 var div=document.createElement(\'div\');\n
 div.className="containerTableStyle";\n
 div.style.width=this.width;\n
 div.style.height=this.height;\n
 this.parentObject.appendChild(div);\n
 return div;\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype._xcloseAll=function(itemObject)\n
{\n
 if(this.rootId!=itemObject.id)this._HideShow(itemObject,1);\n
 for(var i=0;i<itemObject.childsCount;i++)\n
 this._xcloseAll(itemObject.childNodes[i]);\n
};\n
 \n
 dhtmlXTreeObject.prototype._xopenAll=function(itemObject)\n
{\n
 this._HideShow(itemObject,2);\n
 for(var i=0;i<itemObject.childsCount;i++)\n
 this._xopenAll(itemObject.childNodes[i]);\n
};\n
 \n
 dhtmlXTreeObject.prototype._correctPlus=function(itemObject){\n
 \n
 workArray=this.lineArray;\n
 if((this.XMLsource)&&(!itemObject.XMLload))\n
{\n
 var workArray=this.plusArray;\n
 itemObject.htmlNode.childNodes[0].childNodes[0].childNodes[2].childNodes[0].src=this.imPath+itemObject.images[2];\n
}\n
 else\n
 if((itemObject.childsCount)||(itemObject.unParsed))\n
{\n
 if((itemObject.htmlNode.childNodes[0].childNodes[1])&&(itemObject.htmlNode.childNodes[0].childNodes[1].style.display!="none"))\n
{\n
 if(!itemObject.wsign)workArray=this.minusArray;\n
 itemObject.htmlNode.childNodes[0].childNodes[0].childNodes[2].childNodes[0].src=this.imPath+itemObject.images[1];\n
}\n
 else\n
{\n
 if(!itemObject.wsign)workArray=this.plusArray;\n
 itemObject.htmlNode.childNodes[0].childNodes[0].childNodes[2].childNodes[0].src=this.imPath+itemObject.images[2];\n
}\n
}\n
 else\n
{\n
 itemObject.htmlNode.childNodes[0].childNodes[0].childNodes[2].childNodes[0].src=this.imPath+itemObject.images[0];\n
}\n
\n
 \n
 var tempNum=2;\n
 if(!itemObject.treeNod.treeLinesOn)itemObject.htmlNode.childNodes[0].childNodes[0].childNodes[0].childNodes[0].src=this.imPath+workArray[3];\n
 else{\n
 if(itemObject.parentObject)tempNum=this._getCountStatus(itemObject.id,itemObject.parentObject);\n
 itemObject.htmlNode.childNodes[0].childNodes[0].childNodes[0].childNodes[0].src=this.imPath+workArray[tempNum];\n
}\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype._correctLine=function(itemObject){\n
 var sNode=itemObject.parentObject;\n
 try{\n
 if(sNode){\n
 if((this._getLineStatus(itemObject.id,sNode)===0)||(!this.treeLinesOn))\n
{\n
 for(var i=1;i<=itemObject.childsCount;i++)\n
{\n
 itemObject.htmlNode.childNodes[0].childNodes[i].childNodes[0].style.backgroundImage="";\n
 itemObject.htmlNode.childNodes[0].childNodes[i].childNodes[0].style.backgroundRepeat="";\n
}\n
}\n
}\n
 else{\n
 for(i=1;i<=itemObject.childsCount;i++)\n
{\n
 itemObject.htmlNode.childNodes[0].childNodes[i].childNodes[0].style.backgroundImage="url("+this.imPath+"line1.gif)";\n
 itemObject.htmlNode.childNodes[0].childNodes[i].childNodes[0].style.backgroundRepeat="repeat-y";\n
}\n
}\n
}\n
 catch(e){}\n
};\n
 \n
 dhtmlXTreeObject.prototype._getCountStatus=function(itemId,itemObject){\n
 try{\n
 if(itemObject.childsCount<=1){if(itemObject.id==this.rootId)return 4;else return 0;}\n
 \n
 if(itemObject.htmlNode.childNodes[0].childNodes[1].nodem.id==itemId){if(!itemObject.id)return 2;else return 1;}\n
 if(itemObject.htmlNode.childNodes[0].childNodes[itemObject.childsCount].nodem.id==itemId)return 0;\n
}\n
 catch(e){}\n
 return 1;\n
};\n
 \n
 dhtmlXTreeObject.prototype._getLineStatus =function(itemId,itemObject){\n
 if(itemObject.htmlNode.childNodes[0].childNodes[itemObject.childsCount].nodem.id==itemId)return 0;\n
 return 1;\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype._HideShow=function(itemObject,mode){\n
 if((this.XMLsource)&&(!itemObject.XMLload)){itemObject.XMLload=1;this.loadXML(this.XMLsource+getUrlSymbol(this.XMLsource)+"id="+escape(itemObject.id));return;}\n
\n
 var Nodes=itemObject.htmlNode.childNodes[0].childNodes;var Count=Nodes.length;\n
 if(Count>1){\n
 if(((Nodes[1].style.display!="none")||(mode==1))&&(mode!=2)){\n
 \n
 this.allTree.childNodes[0].border = "1";\n
 this.allTree.childNodes[0].border = "0";\n
 nodestyle="none";\n
}\n
 else nodestyle="";\n
 \n
 for(var i=1;i<Count;i++)\n
 Nodes[i].style.display=nodestyle;\n
}\n
 this._correctPlus(itemObject);\n
};\n
 \n
 dhtmlXTreeObject.prototype._getOpenState=function(itemObject){\n
 if(!itemObject)return -1;\n
 var z=itemObject.htmlNode.childNodes[0].childNodes;\n
 if(z.length<=1)return 0;\n
 if(z[1].style.display!="none")return 1;\n
 return -1;\n
};\n
\n
\n
 \n
 \n
 dhtmlXTreeObject.prototype.onRowClick2=function(){\n
 if(this.parentObject.treeNod.dblclickFuncHandler){if(!this.parentObject.treeNod.dblclickFuncHandler(this.parentObject.id))return 0;}\n
 if((this.parentObject.closeble)&&(this.parentObject.closeble!="0"))\n
 this.parentObject.treeNod._HideShow(this.parentObject);\n
 else\n
 this.parentObject.treeNod._HideShow(this.parentObject,2);\n
 return -1;\n
};\n
 \n
 dhtmlXTreeObject.prototype.onRowClick=function(){\n
 if(this.parentObject.treeNod.openFuncHandler){if(!this.parentObject.treeNod.openFuncHandler(this.parentObject.id,this.parentObject.treeNod._getOpenState(this.parentObject)))return 0;}\n
 if((this.parentObject.closeble)&&(this.parentObject.closeble!="0"))\n
 this.parentObject.treeNod._HideShow(this.parentObject);\n
 else\n
 this.parentObject.treeNod._HideShow(this.parentObject,2);\n
 return -1;\n
};\n
\n
\n
 \n
 dhtmlXTreeObject.prototype.onRowClickDown=function(){\n
 var that=this.parentObject.treeNod;\n
 that._selectItem(this.parentObject);\n
 return;\n
};\n
 \n
 dhtmlXTreeObject.prototype._selectItem=function(node){\n
 if(this.lastSelected){\n
 this._unselectItem(this.lastSelected.parentObject);\n
}\n
 var z=node.htmlNode.childNodes[0].childNodes[0].childNodes[3].childNodes[0];\n
 z.className="selectedTreeRow";\n
 this.lastSelected=z.parentNode;\n
};\n
 \n
 dhtmlXTreeObject.prototype._unselectItem=function(node){\n
 node.htmlNode.childNodes[0].childNodes[0].childNodes[3].childNodes[0].className="standartTreeRow";\n
};\n
 \n
 dhtmlXTreeObject.prototype.onRowSelect=function(e,htmlObject,mode){\n
 \n
 if(!htmlObject)htmlObject=this.parentObject.span.parentNode;\n
 htmlObject.parentObject.span.className="selectedTreeRow";\n
 \n
\n
 if(htmlObject.parentObject.scolor)htmlObject.parentObject.span.style.color=htmlObject.parentObject.scolor;\n
 if((htmlObject.parentObject.treeNod.lastSelected)&&(htmlObject.parentObject.treeNod.lastSelected!=htmlObject))\n
{\n
 lastId=htmlObject.parentObject.treeNod.lastSelected.parentObject.id;\n
 htmlObject.parentObject.treeNod.lastSelected.parentObject.span.className="standartTreeRow";\n
 if(htmlObject.parentObject.treeNod.lastSelected.parentObject.acolor)htmlObject.parentObject.treeNod.lastSelected.parentObject.span.style.color=htmlObject.parentObject.treeNod.lastSelected.parentObject.acolor;\n
}\n
 else var lastId="";\n
 htmlObject.parentObject.treeNod.lastSelected=htmlObject;\n
 if(!mode){\n
 if(window.event)e=event;\n
 \n
 if((e)&&(e.button==2)&&(htmlObject.parentObject.treeNod.arFunc))\n
{htmlObject.parentObject.treeNod.arFunc(htmlObject.parentObject.id);}\n
 if(htmlObject.parentObject.actionHandler)htmlObject.parentObject.actionHandler(htmlObject.parentObject.id,lastId);\n
}\n
};\n
 \n
\n
\n
\n
 \n
 \n
dhtmlXTreeObject.prototype._correctCheckStates=function(dhtmlObject){\n
 if(!this.tscheck)return;\n
 if(dhtmlObject.id==this.rootId)return;\n
 \n
 var act=dhtmlObject.htmlNode.childNodes[0].childNodes;\n
 var flag1=0;var flag2=0;\n
 if(act.length<2)return;\n
 for(var i=1;i<act.length;i++){\n
 if(act[i].nodem.checkstate===0)flag1=1;\n
 else if(act[i].nodem.checkstate==1)flag2=1;\n
 else{flag1=1;flag2=1;break;}}\n
\n
 if((flag1)&&(flag2))this._setCheck(dhtmlObject,"notsure");\n
 else if(flag1)this._setCheck(dhtmlObject,false);\n
 else this._setCheck(dhtmlObject,true);\n
 \n
 this._correctCheckStates(dhtmlObject.parentObject);\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype.onCheckBoxClick=function(e){\n
 if(this.treeNod.tscheck){\n
 if(this.parentObject.checkstate==1)this.treeNod._setSubChecked(false,this.parentObject);\n
 else this.treeNod._setSubChecked(true,this.parentObject);\n
 }\n
 else{\n
 if(this.parentObject.checkstate==1)this.treeNod._setCheck(this.parentObject,false);\n
 else this.treeNod._setCheck(this.parentObject,true);}\n
 this.treeNod._correctCheckStates(this.parentObject.parentObject);\n
 if(this.treeNod.checkFuncHandler)return(this.treeNod.checkFuncHandler(this.parentObject.id,this.parentObject.checkstate));\n
 else return true;\n
};\n
 \n
 dhtmlXTreeObject.prototype._createItem=function(acheck,itemObject,mode){\n
 var table=document.createElement(\'table\');\n
 table.cellSpacing=0;table.cellPadding=0;\n
 table.border=0;\n
 if(this.hfMode)table.style.tableLayout="fixed";\n
 table.style.margin=0;table.style.padding=0;\n
\n
 var tbody=document.createElement(\'tbody\');\n
 var tr=document.createElement(\'tr\');\n
 \n
 var td1=document.createElement(\'td\');\n
 td1.className="standartTreeImage";\n
 var img0=document.createElement((itemObject.id==this.rootId)?"div":"img");\n
 img0.border="0";\n
 if(itemObject.id!=this.rootId)img0.align="absmiddle";\n
 td1.appendChild(img0);img0.style.padding=0;img0.style.margin=0;\n
 \n
 var td11=document.createElement(\'td\');\n
 \n
 var inp=document.createElement((itemObject.id==this.rootId)?"div":"img");\n
 inp.checked=0;inp.src=this.imPath+this.checkArray[0];inp.style.width="16px";inp.style.height="16px";\n
 if(!acheck)inp.style.display="none";\n
 \n
 \n
 td11.appendChild(inp);\n
 if(itemObject.id!=this.rootId)inp.align="absmiddle";\n
 inp.onclick=this.onCheckBoxClick;\n
 inp.treeNod=this;\n
 inp.parentObject=itemObject;\n
 td11.width="20px";\n
\n
 var td12=document.createElement(\'td\');\n
 td12.className="standartTreeImage";\n
 var img=document.createElement((itemObject.id==this.rootId)?"div":"img");img.onmousedown=this._preventNsDrag;img.ondragstart=this._preventNsDrag;\n
 img.border="0";\n
 if(this._aimgs){\n
 img.parentObject=itemObject;\n
 if(itemObject.id!=this.rootId)img.align="absmiddle";\n
 img.onclick=this.onRowSelect;}\n
 if(!mode)img.src=this.imPath+this.imageArray[0];\n
 td12.appendChild(img);img.style.padding=0;img.style.margin=0;\n
 if(this.timgen)\n
{img.style.width=this.def_img_x;img.style.height=this.def_img_y;}\n
 else\n
{img.style.width="0px";img.style.height="0px";}\n
 \n
\n
 var td2=document.createElement(\'td\');\n
 td2.className="standartTreeRow";\n
\n
 itemObject.span=document.createElement(\'span\');\n
 itemObject.span.className="standartTreeRow";\n
 if(this.mlitems)itemObject.span.style.width=this.mlitems;\n
 else td2.noWrap=true;\n
 td2.style.width="100%";\n
 itemObject.span.appendChild(document.createTextNode(itemObject.label));\n
 td2.appendChild(itemObject.span);\n
 td2.parentObject=itemObject;td1.parentObject=itemObject;\n
 td2.onclick=this.onRowSelect;td1.onclick=this.onRowClick;td2.ondblclick=this.onRowClick2;\n
 if(this.ettip)td2.title=itemObject.label;\n
 \n
 if(this.dragAndDropOff){\n
 if(this._aimgs){this.dragger.addDraggableItem(td12,this);td12.parentObject=itemObject;}\n
 this.dragger.addDraggableItem(td2,this);\n
}\n
 \n
 itemObject.span.style.paddingLeft="5px";itemObject.span.style.paddinRight="5px";td2.style.verticalAlign="";\n
 td2.style.fontSize="10pt";td2.style.cursor=this.style_pointer;\n
 tr.appendChild(td1);tr.appendChild(td11);tr.appendChild(td12);\n
 tr.appendChild(td2);\n
 tbody.appendChild(tr);\n
 table.appendChild(tbody);\n
\n
 if(this.arFunc){\n
 \n
 tr.oncontextmenu=Function("this.childNodes[0].parentObject.treeNod.arFunc(this.childNodes[0].parentObject.id);return false;");\n
}\n
 return table;\n
};\n
 \n
\n
 \n
 \n
 dhtmlXTreeObject.prototype.setImagePath=function(newPath){this.imPath=newPath;};\n
 \n
\n
\n
 \n
 dhtmlXTreeObject.prototype.setOnRightClickHandler=function(func){if(typeof(func)=="function")this.arFunc=func;else this.arFunc=eval(func);};\n
\n
 \n
 dhtmlXTreeObject.prototype.setOnClickHandler=function(func){if(typeof(func)=="function")this.aFunc=func;else this.aFunc=eval(func);};\n
\n
\n
 \n
 dhtmlXTreeObject.prototype.setXMLAutoLoading=function(filePath){this.XMLsource=filePath;};\n
\n
\n
\n
 \n
 \n
 dhtmlXTreeObject.prototype.setOnCheckHandler=function(func){if(typeof(func)=="function")this.checkFuncHandler=func;else this.checkFuncHandler=eval(func);};\n
\n
\n
 \n
 dhtmlXTreeObject.prototype.setOnOpenHandler=function(func){if(typeof(func)=="function")this.openFuncHandler=func;else this.openFuncHandler=eval(func);};\n
\n
 \n
 dhtmlXTreeObject.prototype.setOnDblClickHandler=function(func){if(typeof(func)=="function")this.dblclickFuncHandler=func;else this.dblclickFuncHandler=eval(func);};\n
 \n
 \n
 \n
\n
\n
\n
\n
\n
\n
 \n
 dhtmlXTreeObject.prototype.openAllItems=function(itemId)\n
{\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 this._xopenAll(temp);\n
 return -1;\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype.getOpenState=function(itemId){\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return "";\n
 return this._getOpenState(temp);\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype.closeAllItems=function(itemId)\n
{\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 this._xcloseAll(temp);\n
 return -1;\n
};\n
 \n
 \n
 \n
 dhtmlXTreeObject.prototype.setUserData=function(itemId,name,value){\n
 var sNode=this._globalIdStorageFind(itemId);\n
 if(!sNode)return -1;\n
 if(name=="hint")sNode.htmlNode.childNodes[0].childNodes[0].title=value;\n
 sNode.userData["t_"+name]=value;\n
 if(!sNode._userdatalist)sNode._userdatalist=name;\n
 else sNode._userdatalist+=","+name;\n
 return -1;\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype.getUserData=function(itemId,name){\n
 var sNode=this._globalIdStorageFind(itemId);\n
 if(!sNode)return -1;\n
 return sNode.userData["t_"+name];\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype.getSelectedItemId=function()\n
{\n
 if(this.lastSelected){\n
 if(this._globalIdStorageFind(this.lastSelected.parentObject.id))\n
 return this.lastSelected.parentObject.id;\n
 }\n
 return("");\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype.getItemColor=function(itemId)\n
{\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
\n
 var res= new Object();\n
//  if(temp.acolor)res.acolor=temp.acolor;\n
//  if(temp.acolor)res.scolor=temp.scolor;\n
//  return res;\n
 return temp.acolor;\n
};\n
 \n
 dhtmlXTreeObject.prototype.setItemColor=function(itemId,defaultColor,selectedColor)\n
{\n
 var temp= "";\n
 if((itemId)&&(itemId.span))\n
 temp=itemId;\n
 else\n
 temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 else{\n
 if((this.lastSelected)&&(temp.tr==this.lastSelected.parentObject.tr))\n
{if(selectedColor)temp.span.style.color=selectedColor;}\n
 else\n
{if(defaultColor)temp.span.style.color=defaultColor;}\n
\n
 if(selectedColor)temp.scolor=selectedColor;\n
 if(defaultColor)temp.acolor=defaultColor;\n
}\n
 return -1;\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype.getItemText=function(itemId)\n
{\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 return(temp.htmlNode.childNodes[0].childNodes[0].childNodes[3].childNodes[0].innerHTML);\n
};\n
 \n
 dhtmlXTreeObject.prototype.getParentId=function(itemId)\n
{\n
 var temp=this._globalIdStorageFind(itemId);\n
 if((!temp)||(!temp.parentObject))return "";\n
 return temp.parentObject.id;\n
};\n
\n
 dhtmlXTreeObject.prototype.getAllParentsIds=function(itemId)\n
{\n
 var temp=this._globalIdStorageFind(itemId);\n
 if((!temp)||(!temp.parentObject))return "";\n
 return this._getAllParentsIds(temp.parentObject.id, temp.parentObject.id);\n
};\n
\n
 dhtmlXTreeObject.prototype._getAllParentsIds=function(itemId, id_list)\n
{\n
 var temp=this._globalIdStorageFind(itemId);\n
 if((!temp)||(!temp.parentObject))return id_list;\n
 return this._getAllParentsIds(temp.parentObject.id, id_list+\',\'+temp.parentObject.id);\n
};\n
 \n
 dhtmlXTreeObject.prototype.changeItemId=function(itemId,newItemId)\n
{\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 temp.id=newItemId;\n
 temp.span.contextMenuId=newItemId;\n
 for(var i=0;i<this._globalIdStorageSize;i++){\n
 if(this._globalIdStorage[i]==itemId)\n
{\n
 this._globalIdStorage[i]=newItemId;\n
}\n
}\n
return -1;\n
};\n
\n
 \n
 \n
 dhtmlXTreeObject.prototype.doCut=function(){\n
 if(this.nodeCut)this.clearCut();\n
 this.nodeCut=this.lastSelected;\n
 if(this.nodeCut)\n
{\n
 var tempa=this.nodeCut.parentObject;\n
 this.cutImg[0]=tempa.images[0];\n
 this.cutImg[1]=tempa.images[1];\n
 this.cutImg[2]=tempa.images[2];\n
 tempa.images[0]=tempa.images[1]=tempa.images[2]=this.cutImage;\n
 this._correctPlus(tempa);\n
}\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype.doPaste=function(itemId){\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 if(this.nodeCut){\n
 if((!this._checkParenNodes(this.nodeCut.parentObject.id,temp))&&(id!=this.nodeCut.parentObject.parentObject.id))\n
 this._moveNode(temp,this.nodeCut.parentObject);\n
 this.clearCut();\n
}\n
return -1;\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype.clearCut=function(){\n
 if(this.nodeCut)\n
{\n
 var tempa=this.nodeCut.parentObject;\n
 tempa.images[0]=this.cutImg[0];\n
 tempa.images[1]=this.cutImg[1];\n
 tempa.images[2]=this.cutImg[2];\n
 if(tempa.parentObject)this._correctPlus(tempa);\n
 if(tempa.parentObject)this._correctLine(tempa);\n
 this.nodeCut=0;\n
}\n
};\n
 \n
\n
\n
 \n
 dhtmlXTreeObject.prototype._moveNode=function(itemObject,targetObject){\n
 \n
 var mode=this.dadmodec;\n
 if(mode==1)\n
{\n
 var z=targetObject;\n
 if(this.dadmodefix<0)\n
{\n
\n
 while(true){\n
 z=this._getPrevNode(z);\n
 if((z==-1)){z=this.htmlNode;break;}\n
 if((z.tr.style.display==="")||(!z.parentObject))break;\n
 \n
 \n
}\n
\n
 var nodeA=z;\n
 var nodeB=targetObject;\n
\n
}\n
 else\n
{\n
 while(true){\n
 z=this._getNextNode(z);\n
 if((z==-1)){z=this.htmlNode;break;}\n
 if((z.tr.style.display==="")||(!z.parentObject))break;\n
 \n
 \n
}\n
\n
 nodeB=z;\n
 nodeA=targetObject;\n
}\n
\n
\n
 if(this._getNodeLevel(nodeA,0)>this._getNodeLevel(nodeB,0))\n
{\n
 return this._moveNodeTo(itemObject,nodeA.parentObject);\n
}\n
 else\n
{\n
 \n
 return this._moveNodeTo(itemObject,nodeB.parentObject,nodeB);\n
}\n
\n
\n
 \n
 \n
\n
}\n
 else return this._moveNodeTo(itemObject,targetObject);\n
 \n
};\n
\n
 \n
\n
dhtmlXTreeObject.prototype._fixNodesCollection=function(target,zParent){\n
 var flag=0;var icount=0;\n
 var Nodes=target.childNodes;\n
 var Count=target.childsCount-1;\n
 \n
 if(zParent==Nodes[Count])return;\n
 for(var i=0;i<Count;i++){\n
 if(Nodes[i]==Nodes[Count]){Nodes[i]=Nodes[i+1];Nodes[i+1]=Nodes[Count];}\n
 }\n
 \n
 for(i=0;i<Count+1;i++)\n
{\n
 if(flag){\n
 var temp=Nodes[i];\n
 Nodes[i]=flag;\n
 flag=temp;\n
}\n
 else \n
 if(Nodes[i]==zParent){flag=Nodes[i];Nodes[i]=Nodes[Count];}\n
}\n
};\n
 \n
\n
 \n
 dhtmlXTreeObject.prototype._moveNodeTo=function(itemObject,targetObject,beforeNode){\n
 var framesMove;\n
 if(targetObject.mytype)\n
 framesMove=(itemObject.treeNod.lWin!=targetObject.lWin);\n
 else\n
 framesMove=(itemObject.treeNod.lWin!=targetObject.treeNod.lWin);\n
\n
 if(this.dragFunc){if(!this.dragFunc(itemObject.id,targetObject.id,(beforeNode?beforeNode.id:null),itemObject.treeNod,targetObject.treeNod))return false;}\n
 if((targetObject.XMLload===0)&&(this.XMLsource))\n
{\n
 targetObject.XMLload=1;this.loadXML(this.XMLsource+getUrlSymbol(this.XMLsource)+"id="+escape(targetObject.id));\n
}\n
 this.openItem(targetObject.id);\n
 \n
 var oldTree=itemObject.treeNod;\n
 var c=itemObject.parentObject.childsCount;\n
 var z=itemObject.parentObject;\n
\n
 if((framesMove)||(oldTree.dpcpy))\n
 itemObject=this._recreateBranch(itemObject,targetObject,beforeNode);\n
 else\n
{\n
\n
 var Count=targetObject.childsCount;var Nodes=targetObject.childNodes;\n
 Nodes[Count]=itemObject;\n
 itemObject.treeNod=targetObject.treeNod;\n
 targetObject.childsCount++;\n
 \n
 var tr=this._drawNewTr(Nodes[Count].htmlNode);\n
 \n
 if(!beforeNode)\n
{\n
 targetObject.htmlNode.childNodes[0].appendChild(tr);\n
 if(this.dadmode==1)this._fixNodesCollection(targetObject,beforeNode);\n
}\n
 else \n
{\n
 targetObject.htmlNode.childNodes[0].insertBefore(tr,beforeNode.tr);\n
 this._fixNodesCollection(targetObject,beforeNode);\n
 Nodes=targetObject.childNodes;\n
}\n
 \n
 \n
}\n
 if(!oldTree.dpcpy){\n
 itemObject.parentObject.htmlNode.childNodes[0].removeChild(itemObject.tr);\n
 if((!beforeNode)||(targetObject!=itemObject.parentObject)){\n
 for(var i=0;i<z.childsCount;i++){\n
 if(z.childNodes[i].id==itemObject.id){\n
 z.childNodes[i]=0;\n
 break;}}}\n
 else z.childNodes[z.childsCount-1]=0;\n
 \n
 oldTree._compressChildList(z.childsCount,z.childNodes);\n
 z.childsCount--;\n
}\n
\n
 \n
 if((!framesMove)&&(!oldTree.dpcpy)){\n
 itemObject.tr=tr;\n
 tr.nodem=itemObject;\n
 itemObject.parentObject=targetObject;\n
 \n
 if(oldTree!=targetObject.treeNod){if(itemObject.treeNod._registerBranch(itemObject,oldTree))return -1;this._clearStyles(itemObject);this._redrawFrom(this,itemObject.parentObject);}\n
 \n
 this._correctPlus(targetObject);\n
 this._correctLine(targetObject);\n
 this._correctLine(itemObject);\n
 this._correctPlus(itemObject);\n
\n
 \n
 if(beforeNode)\n
{\n
 \n
 this._correctPlus(beforeNode);\n
 \n
}\n
 else \n
 if(targetObject.childsCount>=2)\n
{\n
 \n
 this._correctPlus(Nodes[targetObject.childsCount-2]);\n
 this._correctLine(Nodes[targetObject.childsCount-2]);\n
}\n
 \n
 this._correctPlus(Nodes[targetObject.childsCount-1]);\n
 \n
 \n
 \n
 if(this.tscheck)this._correctCheckStates(targetObject);\n
 if(oldTree.tscheck)oldTree._correctCheckStates(z);\n
 \n
}\n
 \n
 \n
 \n
 if(c>1){oldTree._correctPlus(z.childNodes[c-2]);\n
 oldTree._correctLine(z.childNodes[c-2]);\n
}\n
 \n
 oldTree._correctPlus(z);\n
 \n
 \n
 \n
 \n
 if(this.dropFunc)this.dropFunc(itemObject.id,targetObject.id,(beforeNode?beforeNode.id:null),itemObject.treeNod,targetObject.treeNod);\n
 return itemObject.id;\n
};\n
 \n
 \n
dhtmlXTreeObject.prototype._checkParenNodes=function(itemId,htmlObject,shtmlObject){\n
 if(shtmlObject){if(shtmlObject.parentObject.id==htmlObject.id)return 1;}\n
 if(htmlObject.id==itemId)return 1;\n
 if(htmlObject.parentObject)return this._checkParenNodes(itemId,htmlObject.parentObject);else return 0;\n
};\n
 \n
 \n
 \n
 \n
 dhtmlXTreeObject.prototype._clearStyles=function(itemObject){\n
 var td1=itemObject.htmlNode.childNodes[0].childNodes[0].childNodes[1];\n
 var td3=td1.nextSibling.nextSibling;\n
 \n
 itemObject.span.innerHTML=itemObject.label;\n
 \n
 if(this.checkBoxOff){td1.childNodes[0].style.display="";td1.childNodes[0].onclick=this.onCheckBoxClick;}\n
 else td1.childNodes[0].style.display="none";\n
 td1.childNodes[0].treeNod=this;\n
\n
 this.dragger.removeDraggableItem(td3);\n
 if(this.dragAndDropOff)this.dragger.addDraggableItem(td3,this);\n
 td3.childNodes[0].className="standartTreeRow";\n
 td3.onclick=this.onRowSelect;td3.ondblclick=this.onRowClick2;\n
 td1.previousSibling.onclick=this.onRowClick;\n
\n
 this._correctLine(itemObject);\n
 this._correctPlus(itemObject);\n
 for(var i=0;i<itemObject.childsCount;i++)this._clearStyles(itemObject.childNodes[i]);\n
\n
};\n
 \n
 dhtmlXTreeObject.prototype._registerBranch=function(itemObject,oldTree){\n
 \n
 itemObject.id=this._globalIdStorageAdd(itemObject.id,itemObject);\n
 itemObject.treeNod=this;\n
 if(oldTree)oldTree._globalIdStorageSub(itemObject.id);\n
 for(var i=0;i<itemObject.childsCount;i++)\n
 this._registerBranch(itemObject.childNodes[i],oldTree);\n
 return 0;\n
};\n
 \n
 \n
 \n
 dhtmlXTreeObject.prototype.enableThreeStateCheckboxes=function(mode){this.tscheck=convertStringToBoolean(mode);};\n
 \n
\n
\n
\n
\n
 \n
 dhtmlXTreeObject.prototype.enableTreeImages=function(mode){this.timgen=convertStringToBoolean(mode);};\n
 \n
 \n
 \n
 \n
 dhtmlXTreeObject.prototype.enableFixedMode=function(mode){this.hfMode=convertStringToBoolean(mode);};\n
 \n
 \n
 dhtmlXTreeObject.prototype.enableCheckBoxes=function(mode){this.checkBoxOff=convertStringToBoolean(mode);};\n
 \n
 dhtmlXTreeObject.prototype.setStdImages=function(image1,image2,image3){\n
 this.imageArray[0]=image1;this.imageArray[1]=image2;this.imageArray[2]=image3;};\n
\n
 \n
 dhtmlXTreeObject.prototype.enableTreeLines=function(mode){\n
 this.treeLinesOn=convertStringToBoolean(mode);\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype.setImageArrays=function(arrayName,image1,image2,image3,image4,image5){\n
 switch(arrayName){\n
 case "plus": this.plusArray[0]=image1;this.plusArray[1]=image2;this.plusArray[2]=image3;this.plusArray[3]=image4;this.plusArray[4]=image5;break;\n
 case "minus": this.minusArray[0]=image1;this.minusArray[1]=image2;this.minusArray[2]=image3;this.minusArray[3]=image4;this.minusArray[4]=image5;break;\n
 default: break;\n
}\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype.openItem=function(itemId){\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 else return this._openItem(temp);\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype._openItem=function(item){\n
 this._HideShow(item,2);\n
 if((item.parentObject)&&(this._getOpenState(item.parentObject)<0))\n
 this._openItem(item.parentObject);\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype.closeItem=function(itemId){\n
 if(this.rootId==itemId)return 0;\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 if(temp.closeble)\n
 this._HideShow(temp,1);\n
 return -1;\n
};\n
 \n
 \n
\n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 \n
 dhtmlXTreeObject.prototype.getLevel=function(itemId){\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 return this._getNodeLevel(temp,0);\n
};\n
 \n
 \n
\n
 \n
 dhtmlXTreeObject.prototype.setItemCloseable=function(itemId,flag)\n
{\n
 var temp;\n
 flag=convertStringToBoolean(flag);\n
 if((itemId)&&(itemId.span))\n
   temp=itemId;\n
 else \n
   temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 temp.closeble=flag;\n
 return -1;\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype._getNodeLevel=function(itemObject,count){\n
 if(itemObject.parentObject)return this._getNodeLevel(itemObject.parentObject,count+1);\n
 return(count);\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype.hasChildren=function(itemId){\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 else \n
{\n
 if((this.XMLsource)&&(!temp.XMLload))return true;\n
 else \n
 return temp.childsCount;\n
}\n
};\n
 \n
\n
\n
 \n
 \n
 dhtmlXTreeObject.prototype.setItemText=function(itemId,newLabel,newTooltip)\n
{\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 temp.label=newLabel;\n
 temp.span.innerHTML=newLabel;\n
 temp.span.parentNode.title=newTooltip||"";\n
 return -1;\n
};\n
 \n
 dhtmlXTreeObject.prototype.refreshItem=function(itemId){\n
 if(!itemId)itemId=this.rootId;\n
 var temp=this._globalIdStorageFind(itemId);\n
 this.deleteChildItems(itemId);\n
 this.loadXML(this.XMLsource+getUrlSymbol(this.XMLsource)+"id="+escape(itemId));\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype.setItemImage2=function(itemId,image1,image2,image3){\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 temp.images[1]=image2;\n
 temp.images[2]=image3;\n
 temp.images[0]=image1;\n
 this._correctPlus(temp);\n
 return -1;\n
};\n
 \n
 dhtmlXTreeObject.prototype.setItemImage=function(itemId,image1,image2)\n
{\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 if(image2)\n
{\n
 temp.images[1]=image1;\n
 temp.images[2]=image2;\n
}\n
 else temp.images[0]=image1;\n
 this._correctPlus(temp);\n
 return -1;\n
};\n
 \n
 \n
 \n
 dhtmlXTreeObject.prototype.getSubItems =function(itemId)\n
{\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
\n
 var z="";\n
 for(i=0;i<temp.childsCount;i++){\n
 if(!z)z=temp.childNodes[i].id;\n
 else z+=","+temp.childNodes[i].id;}\n
 return z;\n
};\n
 \n
 dhtmlXTreeObject.prototype.getAllSubItems =function(itemId){\n
 return this._getAllSubItems(itemId);\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype._getAllSubItems =function(itemId,z,node)\n
{\n
 if(node)temp=node;\n
 else{\n
 var temp=this._globalIdStorageFind(itemId);\n
}\n
 if(!temp)return 0;\n
 \n
 z="";\n
 for(var i=0;i<temp.childsCount;i++)\n
{\n
 if(!z)z=temp.childNodes[i].id;\n
 else z+=","+temp.childNodes[i].id;\n
 var zb=this._getAllSubItems(0,z,temp.childNodes[i]);\n
 if(zb)z+=","+zb;\n
}\n
 return z;\n
};\n
 \n
\n
 \n
 \n
 dhtmlXTreeObject.prototype.selectItem=function(itemId,mode){\n
 mode=convertStringToBoolean(mode);\n
 var temp=this._globalIdStorageFind(itemId);\n
 if(!temp)return 0;\n
 if(this._getOpenState(temp.parentObject)==-1)\n
 this.openItem(itemId);\n
 \n
 if(mode)\n
 this.onRowSelect(0,temp.htmlNode.childNodes[0].childNodes[0].childNodes[3],false);\n
 else\n
 this.onRowSelect(0,temp.htmlNode.childNodes[0].childNodes[0].childNodes[3],true);\n
 return -1;\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype.getSelectedItemText=function()\n
{\n
 if(this.lastSelected)\n
 return this.lastSelected.parentObject.htmlNode.childNodes[0].childNodes[0].childNodes[3].childNodes[0].innerHTML;\n
 else return("");\n
};\n
\n
\n
\n
\n
 \n
 dhtmlXTreeObject.prototype._compressChildList=function(Count,Nodes)\n
{\n
 Count--;\n
 for(var i=0;i<Count;i++)\n
{\n
 if(Nodes[i]===0){Nodes[i]=Nodes[i+1];Nodes[i+1]=0;}\n
}\n
};\n
 \n
 dhtmlXTreeObject.prototype._deleteNode=function(itemId,htmlObject,skip){\n
\n
 if(!skip){\n
 this._globalIdStorageRecSub(htmlObject);\n
}\n
 \n
 if((!htmlObject)||(!htmlObject.parentObject))return 0;\n
 var tempos=0;var tempos2=0;\n
 if(htmlObject.tr.nextSibling)tempos=htmlObject.tr.nextSibling.nodem;\n
 if(htmlObject.tr.previousSibling)tempos2=htmlObject.tr.previousSibling.nodem;\n
 \n
 var sN=htmlObject.parentObject;\n
 var Count=sN.childsCount;\n
 var Nodes=sN.childNodes;\n
 for(var i=0;i<Count;i++)\n
{\n
 if(Nodes[i].id==itemId){\n
 if(!skip)sN.htmlNode.childNodes[0].removeChild(Nodes[i].tr);\n
 Nodes[i]=0;\n
 break;\n
}\n
}\n
 this._compressChildList(Count,Nodes);\n
 if(!skip){\n
 sN.childsCount--;\n
}\n
\n
 if(tempos){\n
 this._correctPlus(tempos);\n
 this._correctLine(tempos);\n
}\n
 if(tempos2){\n
 this._correctPlus(tempos2);\n
 this._correctLine(tempos2);\n
}\n
 if(this.tscheck)this._correctCheckStates(sN);\n
 return -1;\n
};\n
 \n
 dhtmlXTreeObject.prototype.setCheck=function(itemId,state){\n
 state=convertStringToBoolean(state);\n
 var sNode=this._globalIdStorageFind(itemId);\n
 if(!sNode)return;\n
 if((this.tscheck)&&(this.smcheck))this._setSubChecked(state,sNode);\n
 else this._setCheck(sNode,state);\n
 if(this.smcheck)\n
 this._correctCheckStates(sNode.parentObject);\n
};\n
 \n
 dhtmlXTreeObject.prototype._setCheck=function(sNode,state){\n
 var z=sNode.htmlNode.childNodes[0].childNodes[0].childNodes[1].childNodes[0];\n
 \n
 if(state=="notsure")sNode.checkstate=2;\n
 else if(state)sNode.checkstate=1;else sNode.checkstate=0;\n
\n
 \n
 z.src=this.imPath+this.checkArray[sNode.checkstate];\n
};\n
 \n
 \n
dhtmlXTreeObject.prototype.setSubChecked=function(itemId,state){\n
 var sNode=this._globalIdStorageFind(itemId);\n
 this._setSubChecked(state,sNode);\n
 this._correctCheckStates(sNode.parentObject);\n
};\n
\n
 \n
dhtmlXTreeObject.prototype._setSubCheckedXML=function(state,sNode){\n
 if(!sNode)return;\n
 for(var i=0;i<sNode.childNodes.length;i++){\n
 var tag=sNode.childNodes[i];\n
 if((tag)&&(tag.tagName=="item")){\n
 if(state)tag.setAttribute("checked",1);\n
 else tag.setAttribute("checked","");\n
 this._setSubCheckedXML(state,tag);\n
}\n
}\n
};\n
\n
\n
 \n
 dhtmlXTreeObject.prototype._setSubChecked=function(state,sNode){\n
 state=convertStringToBoolean(state);\n
 if(!sNode)return -1;\n
 if(sNode.unParsed)\n
 this._setSubCheckedXML(state,sNode.unParsed);\n
 for(var i=0;i<sNode.childsCount;i++)\n
{\n
 this._setSubChecked(state,sNode.childNodes[i]);\n
}\n
 var z=sNode.htmlNode.childNodes[0].childNodes[0].childNodes[1].childNodes[0];\n
 \n
 if(state)sNode.checkstate=1;\n
 else sNode.checkstate=0;\n
\n
 z.src=this.imPath+this.checkArray[sNode.checkstate];\n
 return -1;\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype.isItemChecked=function(itemId){\n
 var sNode=this._globalIdStorageFind(itemId);\n
 if(!sNode)return -1;\n
 return sNode.checkstate;\n
};\n
\n
\n
\n
\n
\n
 \n
 dhtmlXTreeObject.prototype.getAllChecked=function(){\n
 return this._getAllChecked("","",1);\n
};\n
\n
 dhtmlXTreeObject.prototype.getAllPartiallyChecked=function(){\n
 return this._getAllPartiallyChecked("","",1);\n
};\n
\n
 dhtmlXTreeObject.prototype.getAllCheckedBranches=function(){\n
 return this._getAllChecked("","",0);\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype._getAllChecked=function(htmlNode,list,mode){\n
 if(!htmlNode)htmlNode=this.htmlNode;\n
 if(((mode)&&(htmlNode.checkstate==1))||((!mode)&&(htmlNode.checkstate>0))){\n
 if(!htmlNode.nocheckbox){if(list)list+=","+htmlNode.id;else list=htmlNode.id;}\n
 }\n
 var j=htmlNode.childsCount;\n
 for(var i=0;i<j;i++)\n
{\n
 list=this._getAllChecked(htmlNode.childNodes[i],list,mode);\n
}\n
 if(htmlNode.unParsed)\n
 list=this._getAllCheckedXML(htmlNode.unParsed,list,mode);\n
\n
 if(list)return list;else return "";\n
};\n
\n
 dhtmlXTreeObject.prototype._getAllPartiallyChecked=function(htmlNode,list,mode){\n
 if(!htmlNode)htmlNode=this.htmlNode;\n
 if(((mode)&&(htmlNode.checkstate==2))||((!mode)&&(htmlNode.checkstate>0))){\n
 if(!htmlNode.nocheckbox){if(list)list+=","+htmlNode.id;else list=htmlNode.id;}\n
 }\n
 var j=htmlNode.childsCount;\n
 for(var i=0;i<j;i++)\n
{\n
 list=this._getAllPartiallyChecked(htmlNode.childNodes[i],list,mode);\n
}\n
 if(htmlNode.unParsed)\n
 list=this._getAllPartiallyCheckedXML(htmlNode.unParsed,list,mode);\n
\n
 if(list)return list;else return "";\n
};\n
\n
 dhtmlXTreeObject.prototype._getAllCheckedXML=function(htmlNode,list,mode){\n
 var j=htmlNode.childNodes.length;\n
 for(var i=0;i<j;i++)\n
{\n
 var tNode=htmlNode.childNodes[i];\n
 if(tNode.tagName=="item")\n
{\n
 var z=tNode.getAttribute("checked");\n
 if((z!==null)&&(z!=="")&&(z!=="0")){\n
 if(((z=="-1")&&(!mode))||(z!="-1")){\n
 if(list)list+=","+tNode.getAttribute("id");\n
 else list=htmlNode.id;\n
 }\n
 }\n
 list=this._getAllChecked(tNode,list,mode);\n
}\n
}\n
\n
 if(list)return list;else return "";\n
};\n
\n
 dhtmlXTreeObject.prototype._getAllPartiallyCheckedXML=function(htmlNode,list,mode){\n
 var j=htmlNode.childNodes.length;\n
 for(var i=0;i<j;i++)\n
{\n
 var tNode=htmlNode.childNodes[i];\n
 if(tNode.tagName=="item")\n
{\n
 var z=tNode.getAttribute("checked");\n
 if((z!==null)&&(z!=="")&&(z!=="0")){\n
 if(((z=="-1")&&(!mode))||(z!="-1")){\n
 if(list)list+=","+tNode.getAttribute("id");\n
 else list=htmlNode.id;}\n
 }\n
 list=this._getAllPartiallyChecked(tNode,list,mode);\n
}\n
}\n
\n
 if(list)return list;else return "";\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype.deleteChildItems=function(itemId)\n
{\n
 var sNode=this._globalIdStorageFind(itemId);\n
 if(!sNode)return;\n
 var j=sNode.childsCount;\n
 for(var i=0;i<j;i++)\n
{\n
 this._deleteNode(sNode.childNodes[0].id,sNode.childNodes[0]);\n
}\n
};\n
\n
 \n
dhtmlXTreeObject.prototype.deleteItem=function(itemId,selectParent){\n
 this._deleteItem(itemId,selectParent);\n
};\n
 \n
dhtmlXTreeObject.prototype._deleteItem=function(itemId,selectParent,skip){\n
 selectParent=convertStringToBoolean(selectParent);\n
 var sNode=this._globalIdStorageFind(itemId);\n
 if(!sNode)return -1;\n
 if(selectParent)this.selectItem(this.getParentId(this.getSelectedItemId()),1);\n
 else\n
 if(sNode==this.lastSelected.parentObject)\n
 this.lastSelected=null;\n
 if(!skip){\n
 this._globalIdStorageRecSub(sNode);\n
 \n
}\n
 var zTemp=sNode.parentObject;\n
 this._deleteNode(itemId,sNode,skip);\n
 this._correctPlus(zTemp);\n
 this._correctLine(zTemp);\n
 return zTemp;\n
\n
\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype._globalIdStorageRecSub=function(itemObject){\n
 for(var i=0;i<itemObject.childsCount;i++)\n
{\n
 this._globalIdStorageRecSub(itemObject.childNodes[i]);\n
 this._globalIdStorageSub(itemObject.childNodes[i].id);\n
}\n
 this._globalIdStorageSub(itemObject.id);\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype.insertNewNext=function(parentItemId,itemId,itemName,itemActionHandler,image1,image2,image3,optionStr,childs){\n
 var sNode=this._globalIdStorageFind(parentItemId);\n
 if((!sNode)||(!sNode.parentObject))return(0);\n
\n
 this._attachChildNode(0,itemId,itemName,itemActionHandler,image1,image2,image3,optionStr,childs,sNode);\n
 return -1;\n
};\n
\n
\n
 \n
 \n
 dhtmlXTreeObject.prototype.getItemIdByIndex=function(itemId,index){\n
 var z=this._globalIdStorageFind(itemId);\n
 if((!z)||(index>z.childsCount))return null;\n
 return z.childNodes[index].id;\n
};\n
\n
 \n
 dhtmlXTreeObject.prototype.getChildItemIdByIndex=function(itemId,index){\n
 var z=this._globalIdStorageFind(itemId);\n
 if((!z)||(index>z.childsCount))return null;\n
 return z.childNodes[index].id;\n
};\n
\n
\n
 \n
 \n
\n
 \n
 dhtmlXTreeObject.prototype.setDragHandler=function(func){if(typeof(func)=="function")this.dragFunc=func;else this.dragFunc=eval(func);};\n
\n
 \n
 dhtmlXTreeObject.prototype._clearMove=function(htmlNode){\n
 if((htmlNode.parentObject)&&(htmlNode.parentObject.span)){\n
 htmlNode.parentObject.span.className=\'standartTreeRow\';\n
 if(htmlNode.parentObject.acolor)htmlNode.parentObject.span.style.color=htmlNode.parentObject.acolor;\n
}\n
 \n
 this.selectionBar.style.display="none";\n
 \n
 this.allTree.className="containerTableStyle";\n
};\n
 \n
 \n
 dhtmlXTreeObject.prototype.enableDragAndDrop=function(mode){\n
 this.dragAndDropOff=convertStringToBoolean(mode);\n
 if(this.dragAndDropOff)this.dragger.addDragLanding(this.allTree,this);\n
};\n
\n
\n
 \n
 dhtmlXTreeObject.prototype._setMove=function(htmlNode,x,y){\n
 if(htmlNode.parentObject.span){\n
 \n
 var a1=getAbsoluteTop(htmlNode);\n
 var a2=getAbsoluteTop(this.allTree);\n
 \n
 this.dadmodec=this.dadmode;\n
 this.dadmodefix=0;\n
\n
\n
 if(this.dadmodec===0)\n
{\n
 htmlNode.parentObject.span.className=\'selectedTreeRow\';\n
 if(htmlNode.parentObject.scolor)htmlNode.parentObject.span.style.color=htmlNode.parentObject.scolor;\n
}\n
 else{\n
 htmlNode.parentObject.span.className=\'standartTreeRow\';\n
 if(htmlNode.parentObject.acolor)htmlNode.parentObject.span.style.color=htmlNode.parentObject.acolor;\n
 this.selectionBar.style.top=a1-a2+16+this.dadmodefix;\n
 this.selectionBar.style.left=5;\n
 this.selectionBar.style.display="";\n
}\n
\n
 \n
 if(this.autoScroll)\n
{\n
 \n
 if((a1-a2-parseInt(this.allTree.scrollTop,10))>(parseInt(this.allTree.offsetHeight,10)-50))\n
 this.allTree.scrollTop=parseInt(this.allTree.scrollTop,10)+20;\n
 \n
 if((a1-a2)<(parseInt(this.allTree.scrollTop,10)+30))\n
 this.allTree.scrollTop=parseInt(this.allTree.scrollTop,10)-20;\n
}\n
}\n
};\n
\n
\n
\n
 \n
dhtmlXTreeObject.prototype._createDragNode=function(htmlObject){\n
 dhtmlObject=htmlObject.parentObject;\n
 if(this.lastSelected)this._clearMove(this.lastSelected);\n
 var dragSpan=document.createElement(\'div\');\n
 dragSpan.innerHTML=dhtmlObject.label;\n
 dragSpan.style.position="absolute";\n
 dragSpan.className="dragSpanDiv";\n
 return dragSpan;\n
};\n
\n
 \n
\n
dhtmlXTreeObject.prototype._preventNsDrag=function(e){\n
 if((e)&&(e.preventDefault)){e.preventDefault();return false;}\n
 return false;\n
};\n
\n
dhtmlXTreeObject.prototype._drag=function(sourceHtmlObject,dhtmlObject,targetHtmlObject){\n
\n
 if(this._autoOpenTimer)clearTimeout(this._autoOpenTimer);\n
\n
 if(!targetHtmlObject.parentObject){\n
 targetHtmlObject=this.htmlNode.htmlNode.childNodes[0].childNodes[0].childNodes[1].childNodes[0];\n
 this.dadmodec=0;\n
}\n
\n
 this._clearMove(targetHtmlObject);\n
 var z=targetHtmlObject.parentObject.treeNod;\n
 z._clearMove("");\n
 \n
 if((!this.dragMove)||(this.dragMove()))\n
{\n
 var newID=this._moveNode(sourceHtmlObject.parentObject,targetHtmlObject.parentObject);\n
 z.selectItem(newID);\n
}\n
\n
};\n
\n
dhtmlXTreeObject.prototype._dragIn=function(htmlObject,shtmlObject,x,y){\n
 if(!htmlObject.parentObject)\n
{\n
 \n
 \n
 this.allTree.className="containerTableStyle selectionBox";\n
 \n
 return htmlObject;\n
 \n
}\n
 \n
 if((!this._checkParenNodes(shtmlObject.parentObject.id,htmlObject.parentObject,shtmlObject.parentObject))&&(htmlObject.parentObject.id!=shtmlObject.parentObject.id))\n
{\n
 htmlObject.parentObject.span.parentNode.appendChild(this.selectionBar);\n
 this._setMove(htmlObject,x,y);\n
 if(this._getOpenState(htmlObject.parentObject)<0)\n
 this._autoOpenTimer=window.setTimeout(new callerFunction(this._autoOpenItem,this),1000);\n
 this._autoOpenId=htmlObject.parentObject.id;\n
 return htmlObject;\n
}\n
 else return 0;\n
};\n
\n
dhtmlXTreeObject.prototype._autoOpenItem=function(e,treeObject){\n
 treeObject.openItem(treeObject._autoOpenId);\n
};\n
\n
dhtmlXTreeObject.prototype._dragOut=function(htmlObject){\n
this._clearMove(htmlObject);\n
if(this._autoOpenTimer)clearTimeout(this._autoOpenTimer);\n
};\n
\n
\n
\n
 \n
dhtmlXTreeObject.prototype._getNextNode=function(item,mode){\n
 if((!mode)&&(item.childsCount))return item.childNodes[0];\n
 if(item==this.htmlNode)\n
 return -1;\n
 if((item.tr)&&(item.tr.nextSibling)&&(item.tr.nextSibling.nodem))\n
 return item.tr.nextSibling.nodem;\n
\n
 return this._getNextNode(item.parentObject,true);\n
};\n
\n
 \n
dhtmlXTreeObject.prototype._lastChild=function(item){\n
 if(item.childsCount)\n
 return this._lastChild(item.childNodes[item.childsCount-1]);\n
 else return item;\n
};\n
\n
 \n
dhtmlXTreeObject.prototype._getPrevNode=function(node,mode){\n
 if((node.tr)&&(node.tr.previousSibling)&&(node.tr.previousSibling.nodem))\n
 return this._lastChild(node.tr.previousSibling.nodem);\n
 \n
 if(node.parentObject)\n
 return node.parentObject;\n
 else return -1;\n
};\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>53613</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
