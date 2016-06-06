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
            <value> <string>ts55133579.12</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>safeimage.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string>var SafeImage = (function() {\n
\n
  var that = {};\n
\n
  that.loadOpenLayerZoomedImage= function(zoomify_width,\n
                                    zoomify_height, zoomify_url,data){\n
    if (that.map !== undefined){\n
        that.map.destroy();\n
    }\n
    /* First we initialize the zoomify pyramid (to get number of tiers) */\n
    that.zoomify = new OpenLayers.Layer.Zoomify( "Zoomify", zoomify_url,data,\n
      new OpenLayers.Size(zoomify_width, zoomify_height ) );\n
\n
    /* Map with raster coordinates (pixels) from Zoomify image */\n
    var options = {\n
        maxExtent: new OpenLayers.Bounds(0, 0, zoomify_width, zoomify_height),\n
        maxResolution: Math.pow(2, that.zoomify.numberOfTiers-1 ),\n
        numZoomLevels: that.zoomify.numberOfTiers,\n
        units: \'pixels\',\n
        size: new OpenLayers.Size(3000,2000)\n
    };\n
\n
    that.map = new OpenLayers.Map("map", options);\n
    that.map.addLayer(that.zoomify);\n
    that.map.setBaseLayer(that.zoomify);\n
    that.map.zoomToMaxExtent();\n
  };\n
  return that\n
}());\n
</string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>1006</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>safeimage.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
