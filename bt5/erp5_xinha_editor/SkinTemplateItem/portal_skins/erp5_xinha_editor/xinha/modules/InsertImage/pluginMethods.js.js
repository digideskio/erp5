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
            <value> <string>ts86919902.46</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>pluginMethods.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/* This compressed file is part of Xinha. For uncompressed sources, forum, and bug reports, go to xinha.org */\n
InsertImage.prototype.show=function(c){if(!this.dialog){this.prepareDialog()}var b=this.editor;if(typeof c=="undefined"){c=b.getParentElement();if(c&&c.tagName.toLowerCase()!="img"){c=null}}if(c){function a(e,g){var d=e.attributes;for(var f=0;f<d.length;f++){if(d[f].nodeName==g&&d[f].specified){return d[f].value}}return""}outparam={f_url:b.stripBaseURL(c.getAttribute("src",2)),f_alt:c.alt,f_border:c.border,f_align:c.align,f_vert:a(c,"vspace"),f_horiz:a(c,"hspace"),f_width:c.width,f_height:c.height}}else{outparam={f_url:"",f_alt:"",f_border:"",f_align:"",f_vert:"",f_horiz:"",f_width:"",f_height:""}}this.image=c;this.dialog.show(outparam)};InsertImage.prototype.apply=function(){var g=this.dialog.hide();if(!g.f_url){return}var c=this.editor;var b=this.image;if(!b){if(Xinha.is_ie){var e=c.getSelection();var a=c.createRange(e);c._doc.execCommand("insertimage",false,g.f_url);b=a.parentElement();if(b.tagName.toLowerCase()!="img"){b=b.previousSibling}}else{b=document.createElement("img");b.src=g.f_url;c.insertNodeAtSelection(b);if(!b.tagName){b=a.startContainer.firstChild}}}else{b.src=g.f_url}for(var f in g){var d=g[f];switch(f){case"f_alt":if(d){b.alt=d}else{b.removeAttribute("alt")}break;case"f_border":if(d){b.border=parseInt(d||"0")}else{b.removeAttribute("border")}break;case"f_align":if(d.value){b.align=d.value}else{b.removeAttribute("align")}break;case"f_vert":if(d!=""){b.vspace=parseInt(d||"0")}else{b.removeAttribute("vspace")}break;case"f_horiz":if(d!=""){b.hspace=parseInt(d||"0")}else{b.removeAttribute("hspace")}break;case"f_width":if(d){b.width=parseInt(d||"0")}else{b.removeAttribute("width")}break;case"f_height":if(d){b.height=parseInt(d||"0")}else{b.removeAttribute("height")}break}}};

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>1827</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>pluginMethods.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
