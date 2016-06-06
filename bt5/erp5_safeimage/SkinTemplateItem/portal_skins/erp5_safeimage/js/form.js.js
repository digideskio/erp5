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
            <value> <string>ts56103844.31</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>form.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/**\n
 * NEXEDI\n
 */\n
(function($) {\n
  \n
   $.getJSON(\n
      \'http://\'+window.location.host+\'/erp5/ERP5Site_getTileImageTransformMetadataList\', \n
       function(data){\n
            for (var i = 0; i < data["image_list"].length; i ++ ) {\n
                \n
\t\tvar aux1= "<li><a href=#image/";\n
\t\tvar aux2= "><i class=icon-star></i>";\n
\t\tvar aux3= "</a></li>";\n
                $(\'.nav-header\').append(aux1+data["image_list"][i]["id"]+aux2+data["image_list"][i]["title"]+aux3)                        \n
        \t    \n
            };\n
        });\n
\n
  var routes = {\n
    "/image/:id" : "displayData",\n
    "image/:id" : "displayData",\n
  }\n
\n
  var router = function(e, d){\n
    var $this = $(this);\n
    $.each(routes, function(pattern, callback){\n
      pattern = pattern.replace(/:\\w+/g, \'([^\\/]+)\');\n
      var regex = new RegExp(\'^\' + pattern + \'$\');\n
      var result = regex.exec(d);\n
      if (result) {\n
        result.shift();\n
        methods[callback].apply($this, result);\n
      }\n
    });\n
  }\n
\n
  var methods = {\n
    init: function() {\n
      // Initialize in this context\n
      var $this = $(this);\n
      // Bind to urlChange event\n
      return this.each(function(){\n
        $.subscribe("urlChange", function(e, d){\n
          router.call($this, e, d);\n
        });\n
      });\n
    },\n
\n
    displayData: function(id){\n
      var zoomify_url, zoomify_width, zoomify_height = null;\n
      zoomify_url = "http://"+window.location.host+"/erp5/image_module/" + id + "/";\n
      //XXX look at the xml definition inside image folder\n
      var zoomify_data = $.getJSON(\n
\t\t\t\t"http://"+window.location.host+"/erp5/image_module/" + id + "/TileImage_getMetadataAsJSON",\n
\t\t\t\tfunction(data){\n
\t\t\t\t\twidth=data["sizes"][0]["width"];\n
\t\t\t\t\theight=data["sizes"][0]["height"];\n
\t\t\t\t  transforms(width,height);\t\t\t\t\t\t\t\n
   \t\t\t\t }\n
\n
\t\t\t);\n
   \n
\t$(this).form(\'render\', \'image\', {\'image_id\': id});\n
\n
\n
  var transforms = function(width,height){\n
                     $.getJSON(\n
                        \'http://\'+window.location.host+\'/erp5/image_module/\'+id+\'/TileImageTransformed_getTransform\',\n
                           function(data){\n
                              pass(width,height,data);\n
                            }\n
                        );\n
    }\n
\n
\tvar pass = function(zoomify_width,zoomify_height,data){\n
\t\t\t\n
\t\t\t\t$(function() {\n
         \t\t\t SafeImage.loadOpenLayerZoomedImage(zoomify_width,zoomify_height, zoomify_url,data);\n
               if (document.location.search != ""){\n
                 SafeImage.map.zoomTo(Number(document.location.search.split("")[6]));\n
                } \n
     \t\t\t\t });\n
\t};\n
\n
    },\n
\n
    render: function(template, data){\n
   \t $(this).html(ich[template](data, true));\n
     }\n
\n
       };\n
\n
  $.fn.form = function(method){\n
    if ( methods[method] ) {\n
      return methods[method].apply( this, Array.prototype.slice.call( arguments, 1 ));\n
    } else if ( typeof method === \'object\' || ! method ) {\n
      return methods.init.apply( this, arguments );\n
    } else {\n
      $.error( \'Method \' +  method + \' does not exist on jQuery.form\' );\n
    }\n
  };\n
})(jQuery);\n
\n
$("#main").form();\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>3048</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>form.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
