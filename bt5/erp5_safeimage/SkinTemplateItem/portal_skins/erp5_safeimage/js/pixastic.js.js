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
            <value> <string>ts54116913.81</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>pixastic.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

var sepia = function (dataI,width,height){\n
\n
    var imagedata = dataI;  \n
    var data = imagedata.data;\n
    var w = width;\n
    var h = height;\n
    var w4 = w*4;\n
    var y = h;\n
    var mode = 1;\n
\n
\n
    /*for(i=0;i<10000000000;i++){\n
      5555*55555554;\n
      i++\n
    };*/ \n
\n
    do {\n
      var offsetY = (y-1)*w4;\n
      var x = w;\n
\n
      do {\n
        var offset = offsetY + (x-1)*4;\n
\n
        if (mode) {\n
\n
          // a bit faster, but not as good\n
\n
          var d = data[offset] * 0.299 + data[offset+1] * 0.587 + data[offset+2] * 0.114;\n
          var r = (d + 39);\n
          var g = (d + 14);\n
          var b = (d - 36);\n
        } else {\n
          // Microsoft\n
          var or = data[offset];\n
          var og = data[offset+1];\n
          var ob = data[offset+2];\n
          var r = (or * 0.393 + og * 0.769 + ob * 0.189);\n
          var g = (or * 0.349 + og * 0.686 + ob * 0.168);\n
          var b = (or * 0.272 + og * 0.534 + ob * 0.131);\n
      }\n
\n
      if (r < 0) r = 0; if (r > 255) r = 255;\n
      if (g < 0) g = 0; if (g > 255) g = 255;\n
      if (b < 0) b = 0; if (b > 255) b = 255;\n
\n
      data[offset] = r;\n
      data[offset+1] = g;\n
      data[offset+2] = b;\n
\n
    } while (--x);\n
  } while (--y);\n
  imagedata.data = data;\n
  return imagedata;\n
};\n
\n
\n
var lighten = function(dataI,width,height,param) {\n
    var imagedata = dataI;\n
    var data = imagedata.data;\n
    var w = width;\n
    var h = height;\n
    var amount = parseFloat(param) || 0;\n
    var mode = 1;\n
\t\tamount = Math.max(-1, Math.min(1, amount));\n
\n
\t\tif (mode) {\n
\n
\t\t\tvar p = w * h;\n
\n
\t\t\tvar pix = p*4, pix1 = pix + 1, pix2 = pix + 2;\n
\t\t\tvar mul = amount + 1;\n
\n
\t\t\twhile (p--) {\n
\t\t\t\tif ((data[pix-=4] = data[pix] * mul) > 255)\n
\t\t\t\t\tdata[pix] = 255;\n
\n
\t\t\t\tif ((data[pix1-=4] = data[pix1] * mul) > 255)\n
\t\t\t\t\tdata[pix1] = 255;\n
\n
\t\t\t\tif ((data[pix2-=4] = data[pix2] * mul) > 255)\n
\t\t\t\t\tdata[pix2] = 255;\n
\n
\t\t\t}\n
\n
\n
\t\t} else {\n
\t\t\t/*var img = params.image;\n
\t\t\tif (amount < 0) {\n
\t\t\t\timg.style.filter += " light()";\n
\t\t\t\timg.filters[img.filters.length-1].addAmbient(\n
\t\t\t\t\t255,255,255,\n
\t\t\t\t\t100 * -amount\n
\t\t\t\t);\n
\t\t\t} else if (amount > 0) {\n
\t\t\t\timg.style.filter += " light()";\n
\t\t\t\timg.filters[img.filters.length-1].addAmbient(\n
\t\t\t\t\t255,255,255,\n
\t\t\t\t\t100\n
\t\t\t\t);\n
\t\t\t\timg.filters[img.filters.length-1].addAmbient(\n
\t\t\t\t\t255,255,255,\n
\t\t\t\t\t100 * amount\n
\t\t\t\t);*/\n
        console.log("Internet Explorer is crap");\n
\t\t\t}\n
\t\t\n
\t\n
\t\timagedata.data = data;  \n
    return imagedata;\n
\t\n
};\n
\n
\n
var brightness = function(dataI,width,height,param1,param2) {\n
\n
    var imagedata = dataI;\n
    var data = imagedata.data;\n
    var w = width;\n
    var h = height;\n
    var brightness = parseInt(param1,10) || 0;\n
\t\tvar contrast = parseFloat(param2)||0;\n
\t\t//var legacy = !!(params.options.legacy && params.options.legacy != "false");\n
    var mode = 1;\n
  \tbrightness = Math.min(150,Math.max(-150,brightness));\n
\t\t\n
\t\t//var brightMul = 1 + Math.min(150,Math.max(-150,brightness)) / 150;\n
\t  contrast = Math.max(0,contrast+1);\n
\n
\t\tif (mode) {\n
\t\t\tvar p = w*h;\n
\t\t\tvar pix = p*4, pix1, pix2;\n
\n
\t\t\tvar mul, add;\n
\t\t\tif (contrast != 1) {\n
\t\t\t\t\tmul = contrast;\n
\t\t\t\t\tadd = (brightness - 128) * contrast + 128;\n
\t\t\t} else {  // this if-then is not necessary anymore, is it?\n
\t\t\t\t\tmul = 1;\n
\t\t\t\t\tadd = brightness;\n
\t\t\t}\n
\t\t\tvar r, g, b;\n
\t\t\twhile (p--) {\n
\t\t\t\tif ((r = data[pix-=4] * mul + add) > 255 )\n
\t\t\t\t\tdata[pix] = 255;\n
\t\t\t\telse if (r < 0)\n
\t\t\t\t\tdata[pix] = 0;\n
\t\t\t\telse\n
 \t\t\t\t\tdata[pix] = r;\n
\n
\t\t\t\tif ((g = data[pix1=pix+1] * mul + add) > 255 ) \n
\t\t\t\t\tdata[pix1] = 255;\n
\t\t\t\telse if (g < 0)\n
\t\t\t\t\tdata[pix1] = 0;\n
\t\t\t\telse\n
\t\t\t\t\tdata[pix1] = g;\n
\n
\t\t\t\tif ((b = data[pix2=pix+2] * mul + add) > 255 ) \n
\t\t\t\t\tdata[pix2] = 255;\n
\t\t\t\telse if (b < 0)\n
\t\t\t\t\tdata[pix2] = 0;\n
\t\t\t\telse\n
\t\t\t\t\tdata[pix2] = b;\n
\t\t\t}\n
\t\t}\n
\t\n
  imagedata.data = data;\n
  return imagedata;\n
\t\n
};\n
\n
\n
var posterize = function(dataI,width,height,param1) {\n
\n
    var imagedata = dataI;\n
    var data = imagedata.data;\n
    var w = width;\n
    var h = height;\n
\t\tvar numLevels = 256;\n
    var mode = 1;\n
    var aux = param1;\n
    \n
\t\tif (typeof aux != "undefined")\n
\t\t\tnumLevels = parseInt(aux,10)||1;\n
\n
\t\tif (mode) {\n
\n
\t\t\tnumLevels = Math.max(2,Math.min(256,numLevels));\n
\t\n
\t\t\tvar numAreas = 256 / numLevels;\n
\t\t\tvar numValues = 256 / (numLevels-1);\n
\n
\t\t\tvar w4 = w*4;\n
\t\t\tvar y = h;\n
\t\t\tdo {\n
\t\t\t\tvar offsetY = (y-1)*w4;\n
\t\t\t\tvar x = w;\n
\t\t\t\tdo {\n
\t\t\t\t\tvar offset = offsetY + (x-1)*4;\n
\n
\t\t\t\t\tvar r = numValues * ((data[offset] / numAreas)>>0);\n
\t\t\t\t\tvar g = numValues * ((data[offset+1] / numAreas)>>0);\n
\t\t\t\t\tvar b = numValues * ((data[offset+2] / numAreas)>>0);\n
\n
\t\t\t\t\tif (r > 255) r = 255;\n
\t\t\t\t\tif (g > 255) g = 255;\n
\t\t\t\t\tif (b > 255) b = 255;\n
\n
\t\t\t\t\tdata[offset] = r;\n
\t\t\t\t\tdata[offset+1] = g;\n
\t\t\t\t\tdata[offset+2] = b;\n
\n
\t\t\t\t} while (--x);\n
\t\t\t} while (--y);\n
\t\t}\n
\t  imagedata.data;\n
  \treturn imagedata;\n
};\n
\n
\n
var noise = function(dataI,width,height) {\n
\n
    var imagedata = dataI;\n
    var data = imagedata.data;\n
    var w = width;\n
    var h = height;\n
    var mode = 1;\n
\t\tvar w4 = w*4;\n
\t\tvar y = h;\n
\n
\n
\t\t\tdo {\n
\t\t\t\tvar offsetY = (y-1)*w4;\n
\n
\t\t\t\tvar nextY = (y == h) ? y - 1 : y;\n
\t\t\t\tvar prevY = (y == 1) ? 0 : y-2;\n
\n
\t\t\t\tvar offsetYPrev = prevY*w*4;\n
\t\t\t\tvar offsetYNext = nextY*w*4;\n
\n
\t\t\t\tvar x = w;\n
\t\t\t\tdo {\n
\t\t\t\t\tvar offset = offsetY + (x*4-4);\n
\n
\t\t\t\t\tvar offsetPrev = offsetYPrev + ((x == 1) ? 0 : x-2) * 4;\n
\t\t\t\t\tvar offsetNext = offsetYNext + ((x == w) ? x-1 : x) * 4;\n
\n
\t\t\t\t\tvar minR, maxR, minG, maxG, minB, maxB;\n
\n
\t\t\t\t\tminR = maxR = data[offsetPrev];\n
\t\t\t\t\tvar r1 = data[offset-4], r2 = data[offset+4], r3 = data[offsetNext];\n
\t\t\t\t\tif (r1 < minR) minR = r1;\n
\t\t\t\t\tif (r2 < minR) minR = r2;\n
\t\t\t\t\tif (r3 < minR) minR = r3;\n
\t\t\t\t\tif (r1 > maxR) maxR = r1;\n
\t\t\t\t\tif (r2 > maxR) maxR = r2;\n
\t\t\t\t\tif (r3 > maxR) maxR = r3;\n
\n
\t\t\t\t\tminG = maxG = data[offsetPrev+1];\n
\t\t\t\t\tvar g1 = data[offset-3], g2 = data[offset+5], g3 = data[offsetNext+1];\n
\t\t\t\t\tif (g1 < minG) minG = g1;\n
\t\t\t\t\tif (g2 < minG) minG = g2;\n
\t\t\t\t\tif (g3 < minG) minG = g3;\n
\t\t\t\t\tif (g1 > maxG) maxG = g1;\n
\t\t\t\t\tif (g2 > maxG) maxG = g2;\n
\t\t\t\t\tif (g3 > maxG) maxG = g3;\n
\n
\t\t\t\t\tminB = maxB = data[offsetPrev+2];\n
\t\t\t\t\tvar b1 = data[offset-2], b2 = data[offset+6], b3 = data[offsetNext+2];\n
\t\t\t\t\tif (b1 < minB) minB = b1;\n
\t\t\t\t\tif (b2 < minB) minB = b2;\n
\t\t\t\t\tif (b3 < minB) minB = b3;\n
\t\t\t\t\tif (b1 > maxB) maxB = b1;\n
\t\t\t\t\tif (b2 > maxB) maxB = b2;\n
\t\t\t\t\tif (b3 > maxB) maxB = b3;\n
\n
\t\t\t\t\tif (data[offset] > maxR) {\n
\t\t\t\t\t\tdata[offset] = maxR;\n
\t\t\t\t\t} else if (data[offset] < minR) {\n
\t\t\t\t\t\tdata[offset] = minR;\n
\t\t\t\t\t}\n
\t\t\t\t\tif (data[offset+1] > maxG) {\n
\t\t\t\t\t\tdata[offset+1] = maxG;\n
\t\t\t\t\t} else if (data[offset+1] < minG) {\n
\t\t\t\t\t\tdata[offset+1] = minG;\n
\t\t\t\t\t}\n
\t\t\t\t\tif (data[offset+2] > maxB) {\n
\t\t\t\t\t\tdata[offset+2] = maxB;\n
\t\t\t\t\t} else if (data[offset+2] < minB) {\n
\t\t\t\t\t\tdata[offset+2] = minB;\n
\t\t\t\t\t}\n
\n
\t\t\t\t} while (--x);\n
\t\t\t} while (--y);\n
\n
    imagedata.data = data;\n
\t\treturn imagedata;\n
\n
}\n
\n
var edges = function(dataI,width,height) {\n
    var imagedata = dataI;\n
    var data = imagedata.data;\n
    var dataCopy = data;\n
    var w = width;\n
    var h = height;\n
    var mono = false;\n
    var invert = false;\n
    var mode = 1;\n
\n
\t\tvar c = -1/8;\n
\t\tvar kernel = [\n
\t\t\t\t[c, \tc, \tc],\n
\t\t\t\t[c, \t1, \tc],\n
\t\t\t\t[c, \tc, \tc]\n
\t\t];\n
\n
\t\tweight = 1/c;\n
\n
\t\tvar w4 = w*4;\n
\t\tvar y = h;\n
\t\t\tdo {\n
\t\t\t\tvar offsetY = (y-1)*w4;\n
\n
\t\t\t\tvar nextY = (y == h) ? y - 1 : y;\n
\t\t\t\tvar prevY = (y == 1) ? 0 : y-2;\n
\n
\t\t\t\tvar offsetYPrev = prevY*w*4;\n
\t\t\t\tvar offsetYNext = nextY*w*4;\n
\n
\t\t\t\tvar x = w;\n
\t\t\t\tdo {\n
\t\t\t\t\tvar offset = offsetY + (x*4-4);\n
\n
\t\t\t\t\tvar offsetPrev = offsetYPrev + ((x == 1) ? 0 : x-2) * 4;\n
\t\t\t\t\tvar offsetNext = offsetYNext + ((x == w) ? x-1 : x) * 4;\n
\t\n
\t\t\t\t\tvar r = ((dataCopy[offsetPrev-4]\n
\t\t\t\t\t\t+ dataCopy[offsetPrev]\n
\t\t\t\t\t\t+ dataCopy[offsetPrev+4]\n
\t\t\t\t\t\t+ dataCopy[offset-4]\n
\t\t\t\t\t\t+ dataCopy[offset+4]\n
\t\t\t\t\t\t+ dataCopy[offsetNext-4]\n
\t\t\t\t\t\t+ dataCopy[offsetNext]\n
\t\t\t\t\t\t+ dataCopy[offsetNext+4]) * c\n
\t\t\t\t\t\t+ dataCopy[offset]\n
\t\t\t\t\t\t) \n
\t\t\t\t\t\t* weight;\n
\t\n
\t\t\t\t\tvar g = ((dataCopy[offsetPrev-3]\n
\t\t\t\t\t\t+ dataCopy[offsetPrev+1]\n
\t\t\t\t\t\t+ dataCopy[offsetPrev+5]\n
\t\t\t\t\t\t+ dataCopy[offset-3]\n
\t\t\t\t\t\t+ dataCopy[offset+5]\n
\t\t\t\t\t\t+ dataCopy[offsetNext-3]\n
\t\t\t\t\t\t+ dataCopy[offsetNext+1]\n
\t\t\t\t\t\t+ dataCopy[offsetNext+5]) * c\n
\t\t\t\t\t\t+ dataCopy[offset+1])\n
\t\t\t\t\t\t* weight;\n
\t\n
\t\t\t\t\tvar b = ((dataCopy[offsetPrev-2]\n
\t\t\t\t\t\t+ dataCopy[offsetPrev+2]\n
\t\t\t\t\t\t+ dataCopy[offsetPrev+6]\n
\t\t\t\t\t\t+ dataCopy[offset-2]\n
\t\t\t\t\t\t+ dataCopy[offset+6]\n
\t\t\t\t\t\t+ dataCopy[offsetNext-2]\n
\t\t\t\t\t\t+ dataCopy[offsetNext+2]\n
\t\t\t\t\t\t+ dataCopy[offsetNext+6]) * c\n
\t\t\t\t\t\t+ dataCopy[offset+2])\n
\t\t\t\t\t\t* weight;\n
\n
\t\t\t\t\tif (mono) {\n
\t\t\t\t\t\tvar brightness = (r*0.3 + g*0.59 + b*0.11)||0;\n
\t\t\t\t\t\tif (invert) brightness = 255 - brightness;\n
\t\t\t\t\t\tif (brightness < 0 ) brightness = 0;\n
\t\t\t\t\t\tif (brightness > 255 ) brightness = 255;\n
\t\t\t\t\t\tr = g = b = brightness;\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tif (invert) {\n
\t\t\t\t\t\t\tr = 255 - r;\n
\t\t\t\t\t\t\tg = 255 - g;\n
\t\t\t\t\t\t\tb = 255 - b;\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tif (r < 0 ) r = 0;\n
\t\t\t\t\t\tif (g < 0 ) g = 0;\n
\t\t\t\t\t\tif (b < 0 ) b = 0;\n
\t\t\t\t\t\tif (r > 255 ) r = 255;\n
\t\t\t\t\t\tif (g > 255 ) g = 255;\n
\t\t\t\t\t\tif (b > 255 ) b = 255;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tdata[offset] = r;\n
\t\t\t\t\tdata[offset+1] = g;\n
\t\t\t\t\tdata[offset+2] = b;\n
\n
\t\t\t\t} while (--x);\n
\t\t\t} while (--y);\n
    imagedata.data = data;\n
\t\treturn imagedata;\n
};\n
\n
\n
self.addEventListener("message", function(e){\n
    var data = e.data;\n
    var result = edges(data.image,data.width,data.height);\n
    self.postMessage(result);\n
},false);\n
\n
  \n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>9185</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>pixastic.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
