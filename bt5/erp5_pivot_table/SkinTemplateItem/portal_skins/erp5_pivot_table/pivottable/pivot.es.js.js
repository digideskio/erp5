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
            <value> <string>ts32626250.5</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>pivot.es.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

(function() {\n
  var callWithJQuery;\n
\n
  callWithJQuery = function(pivotModule) {\n
    if (typeof exports === "object" && typeof module === "object") {\n
      return pivotModule(require("jquery"));\n
    } else if (typeof define === "function" && define.amd) {\n
      return define(["jquery"], pivotModule);\n
    } else {\n
      return pivotModule(jQuery);\n
    }\n
  };\n
\n
  callWithJQuery(function($) {\n
    var frFmt, frFmtInt, frFmtPct, nf, tpl;\n
    nf = $.pivotUtilities.numberFormat;\n
    tpl = $.pivotUtilities.aggregatorTemplates;\n
    frFmt = nf({\n
      thousandsSep: " ",\n
      decimalSep: ","\n
    });\n
    frFmtInt = nf({\n
      digitsAfterDecimal: 0,\n
      thousandsSep: " ",\n
      decimalSep: ","\n
    });\n
    frFmtPct = nf({\n
      digitsAfterDecimal: 1,\n
      scaler: 100,\n
      suffix: "%",\n
      thousandsSep: " ",\n
      decimalSep: ","\n
    });\n
    return $.pivotUtilities.locales.es = {\n
      localeStrings: {\n
        renderError: "Ocurri&oacute; un error durante la interpretaci&oacute;n de la tabla din&acute;mica.",\n
        computeError: "Ocurri&oacute; un error durante el c&acute;lculo de la tabla din&acute;mica.",\n
        uiRenderError: "Ocurri&oacute; un error durante el dibujado de la tabla din&acute;mica.",\n
        selectAll: "Seleccionar todo",\n
        selectNone: "Deseleccionar todo",\n
        tooMany: "(demasiados valores)",\n
        filterResults: "Filtrar resultados",\n
        totals: "Totales",\n
        vs: "vs",\n
        by: "por"\n
      },\n
      aggregators: {\n
        "Cuenta": tpl.count(frFmtInt),\n
        "Cuenta de valores &uacute;nicos": tpl.countUnique(frFmtInt),\n
        "Lista de valores &uacute;nicos": tpl.listUnique(", "),\n
        "Suma": tpl.sum(frFmt),\n
        "Suma de enteros": tpl.sum(frFmtInt),\n
        "Promedio": tpl.average(frFmt),\n
        "Mínimo": tpl.min(frFmt),\n
        "Máximo": tpl.max(frFmt),\n
        "Suma de sumas": tpl.sumOverSum(frFmt),\n
        "Cota 80% superior": tpl.sumOverSumBound80(true, frFmt),\n
        "Cota 80% inferior": tpl.sumOverSumBound80(false, frFmt),\n
        "Proporci&oacute;n del total (suma)": tpl.fractionOf(tpl.sum(), "total", frFmtPct),\n
        "Proporci&oacute;n de la fila (suma)": tpl.fractionOf(tpl.sum(), "row", frFmtPct),\n
        "Proporci&oacute;n de la columna (suma)": tpl.fractionOf(tpl.sum(), "col", frFmtPct),\n
        "Proporci&oacute;n del total (cuenta)": tpl.fractionOf(tpl.count(), "total", frFmtPct),\n
        "Proporci&oacute;n de la fila (cuenta)": tpl.fractionOf(tpl.count(), "row", frFmtPct),\n
        "Proporci&oacute;n de la columna (cuenta)": tpl.fractionOf(tpl.count(), "col", frFmtPct)\n
      },\n
      renderers: {\n
        "Tabla": $.pivotUtilities.renderers["Table"],\n
        "Tabla con barras": $.pivotUtilities.renderers["Table Barchart"],\n
        "Heatmap": $.pivotUtilities.renderers["Heatmap"],\n
        "Heatmap por filas": $.pivotUtilities.renderers["Row Heatmap"],\n
        "Heatmap por columnas": $.pivotUtilities.renderers["Col Heatmap"]\n
      }\n
    };\n
  });\n
\n
}).call(this);\n
\n
//# sourceMappingURL=pivot.es.js.map

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>3015</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
