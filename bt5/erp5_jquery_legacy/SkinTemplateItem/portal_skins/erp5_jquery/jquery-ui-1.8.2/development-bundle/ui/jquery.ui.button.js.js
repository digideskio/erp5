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
            <value> <string>ts77895655.75</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>jquery.ui.button.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * jQuery UI Button 1.8.2\n
 *\n
 * Copyright (c) 2010 AUTHORS.txt (http://jqueryui.com/about)\n
 * Dual licensed under the MIT (MIT-LICENSE.txt)\n
 * and GPL (GPL-LICENSE.txt) licenses.\n
 *\n
 * http://docs.jquery.com/UI/Button\n
 *\n
 * Depends:\n
 *\tjquery.ui.core.js\n
 *\tjquery.ui.widget.js\n
 */\n
(function( $ ) {\n
\n
var lastActive,\n
\tbaseClasses = "ui-button ui-widget ui-state-default ui-corner-all",\n
\tstateClasses = "ui-state-hover ui-state-active ",\n
\ttypeClasses = "ui-button-icons-only ui-button-icon-only ui-button-text-icons ui-button-text-icon ui-button-text-only",\n
\tformResetHandler = function( event ) {\n
\t\t$( ":ui-button", event.target.form ).each(function() {\n
\t\t\tvar inst = $( this ).data( "button" );\n
\t\t\tsetTimeout(function() {\n
\t\t\t\tinst.refresh();\n
\t\t\t}, 1 );\n
\t\t});\n
\t},\n
\tradioGroup = function( radio ) {\n
\t\tvar name = radio.name,\n
\t\t\tform = radio.form,\n
\t\t\tradios = $( [] );\n
\t\tif ( name ) {\n
\t\t\tif ( form ) {\n
\t\t\t\tradios = $( form ).find( "[name=\'" + name + "\']" );\n
\t\t\t} else {\n
\t\t\t\tradios = $( "[name=\'" + name + "\']", radio.ownerDocument )\n
\t\t\t\t\t.filter(function() {\n
\t\t\t\t\t\treturn !this.form;\n
\t\t\t\t\t});\n
\t\t\t}\n
\t\t}\n
\t\treturn radios;\n
\t};\n
\n
$.widget( "ui.button", {\n
\toptions: {\n
\t\ttext: true,\n
\t\tlabel: null,\n
\t\ticons: {\n
\t\t\tprimary: null,\n
\t\t\tsecondary: null\n
\t\t}\n
\t},\n
\t_create: function() {\n
\t\tthis.element.closest( "form" )\n
\t\t\t.unbind( "reset.button" )\n
\t\t\t.bind( "reset.button", formResetHandler );\n
\n
\t\tthis._determineButtonType();\n
\t\tthis.hasTitle = !!this.buttonElement.attr( "title" );\n
\n
\t\tvar self = this,\n
\t\t\toptions = this.options,\n
\t\t\ttoggleButton = this.type === "checkbox" || this.type === "radio",\n
\t\t\thoverClass = "ui-state-hover" + ( !toggleButton ? " ui-state-active" : "" ),\n
\t\t\tfocusClass = "ui-state-focus";\n
\n
\t\tif ( options.label === null ) {\n
\t\t\toptions.label = this.buttonElement.html();\n
\t\t}\n
\n
\t\tif ( this.element.is( ":disabled" ) ) {\n
\t\t\toptions.disabled = true;\n
\t\t}\n
\n
\t\tthis.buttonElement\n
\t\t\t.addClass( baseClasses )\n
\t\t\t.attr( "role", "button" )\n
\t\t\t.bind( "mouseenter.button", function() {\n
\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\t$( this ).addClass( "ui-state-hover" );\n
\t\t\t\tif ( this === lastActive ) {\n
\t\t\t\t\t$( this ).addClass( "ui-state-active" );\n
\t\t\t\t}\n
\t\t\t})\n
\t\t\t.bind( "mouseleave.button", function() {\n
\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\treturn;\n
\t\t\t\t}\n
\t\t\t\t$( this ).removeClass( hoverClass );\n
\t\t\t})\n
\t\t\t.bind( "focus.button", function() {\n
\t\t\t\t// no need to check disabled, focus won\'t be triggered anyway\n
\t\t\t\t$( this ).addClass( focusClass );\n
\t\t\t})\n
\t\t\t.bind( "blur.button", function() {\n
\t\t\t\t$( this ).removeClass( focusClass );\n
\t\t\t});\n
\n
\t\tif ( toggleButton ) {\n
\t\t\tthis.element.bind( "change.button", function() {\n
\t\t\t\tself.refresh();\n
\t\t\t});\n
\t\t}\n
\n
\t\tif ( this.type === "checkbox" ) {\n
\t\t\tthis.buttonElement.bind( "click.button", function() {\n
\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t\t$( this ).toggleClass( "ui-state-active" );\n
\t\t\t\tself.buttonElement.attr( "aria-pressed", self.element[0].checked );\n
\t\t\t});\n
\t\t} else if ( this.type === "radio" ) {\n
\t\t\tthis.buttonElement.bind( "click.button", function() {\n
\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t\t$( this ).addClass( "ui-state-active" );\n
\t\t\t\tself.buttonElement.attr( "aria-pressed", true );\n
\n
\t\t\t\tvar radio = self.element[ 0 ];\n
\t\t\t\tradioGroup( radio )\n
\t\t\t\t\t.not( radio )\n
\t\t\t\t\t.map(function() {\n
\t\t\t\t\t\treturn $( this ).button( "widget" )[ 0 ];\n
\t\t\t\t\t})\n
\t\t\t\t\t.removeClass( "ui-state-active" )\n
\t\t\t\t\t.attr( "aria-pressed", false );\n
\t\t\t});\n
\t\t} else {\n
\t\t\tthis.buttonElement\n
\t\t\t\t.bind( "mousedown.button", function() {\n
\t\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t\t$( this ).addClass( "ui-state-active" );\n
\t\t\t\t\tlastActive = this;\n
\t\t\t\t\t$( document ).one( "mouseup", function() {\n
\t\t\t\t\t\tlastActive = null;\n
\t\t\t\t\t});\n
\t\t\t\t})\n
\t\t\t\t.bind( "mouseup.button", function() {\n
\t\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t\t$( this ).removeClass( "ui-state-active" );\n
\t\t\t\t})\n
\t\t\t\t.bind( "keydown.button", function(event) {\n
\t\t\t\t\tif ( options.disabled ) {\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t\tif ( event.keyCode == $.ui.keyCode.SPACE || event.keyCode == $.ui.keyCode.ENTER ) {\n
\t\t\t\t\t\t$( this ).addClass( "ui-state-active" );\n
\t\t\t\t\t}\n
\t\t\t\t})\n
\t\t\t\t.bind( "keyup.button", function() {\n
\t\t\t\t\t$( this ).removeClass( "ui-state-active" );\n
\t\t\t\t});\n
\n
\t\t\tif ( this.buttonElement.is("a") ) {\n
\t\t\t\tthis.buttonElement.keyup(function(event) {\n
\t\t\t\t\tif ( event.keyCode === $.ui.keyCode.SPACE ) {\n
\t\t\t\t\t\t// TODO pass through original event correctly (just as 2nd argument doesn\'t work)\n
\t\t\t\t\t\t$( this ).click();\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t}\n
\t\t}\n
\n
\t\t// TODO: pull out $.Widget\'s handling for the disabled option into\n
\t\t// $.Widget.prototype._setOptionDisabled so it\'s easy to proxy and can\n
\t\t// be overridden by individual plugins\n
\t\tthis._setOption( "disabled", options.disabled );\n
\t},\n
\n
\t_determineButtonType: function() {\n
\t\t\n
\t\tif ( this.element.is(":checkbox") ) {\n
\t\t\tthis.type = "checkbox";\n
\t\t} else {\n
\t\t\tif ( this.element.is(":radio") ) {\n
\t\t\t\tthis.type = "radio";\n
\t\t\t} else {\n
\t\t\t\tif ( this.element.is("input") ) {\n
\t\t\t\t\tthis.type = "input";\n
\t\t\t\t} else {\n
\t\t\t\t\tthis.type = "button";\n
\t\t\t\t}\n
\t\t\t}\n
\t\t}\n
\t\t\n
\t\tif ( this.type === "checkbox" || this.type === "radio" ) {\n
\t\t\t// we don\'t search against the document in case the element\n
\t\t\t// is disconnected from the DOM\n
\t\t\tthis.buttonElement = this.element.parents().last()\n
\t\t\t\t.find( "[for=" + this.element.attr("id") + "]" );\n
\t\t\tthis.element.addClass( "ui-helper-hidden-accessible" );\n
\n
\t\t\tvar checked = this.element.is( ":checked" );\n
\t\t\tif ( checked ) {\n
\t\t\t\tthis.buttonElement.addClass( "ui-state-active" );\n
\t\t\t}\n
\t\t\tthis.buttonElement.attr( "aria-pressed", checked );\n
\t\t} else {\n
\t\t\tthis.buttonElement = this.element;\n
\t\t}\n
\t},\n
\n
\twidget: function() {\n
\t\treturn this.buttonElement;\n
\t},\n
\n
\tdestroy: function() {\n
\t\tthis.element\n
\t\t\t.removeClass( "ui-helper-hidden-accessible" );\n
\t\tthis.buttonElement\n
\t\t\t.removeClass( baseClasses + " " + stateClasses + " " + typeClasses )\n
\t\t\t.removeAttr( "role" )\n
\t\t\t.removeAttr( "aria-pressed" )\n
\t\t\t.html( this.buttonElement.find(".ui-button-text").html() );\n
\n
\t\tif ( !this.hasTitle ) {\n
\t\t\tthis.buttonElement.removeAttr( "title" );\n
\t\t}\n
\n
\t\t$.Widget.prototype.destroy.call( this );\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\t$.Widget.prototype._setOption.apply( this, arguments );\n
\t\tif ( key === "disabled" ) {\n
\t\t\tif ( value ) {\n
\t\t\t\tthis.element.attr( "disabled", true );\n
\t\t\t} else {\n
\t\t\t\tthis.element.removeAttr( "disabled" );\n
\t\t\t}\n
\t\t}\n
\t\tthis._resetButton();\n
\t},\n
\n
\trefresh: function() {\n
\t\tvar isDisabled = this.element.is( ":disabled" );\n
\t\tif ( isDisabled !== this.options.disabled ) {\n
\t\t\tthis._setOption( "disabled", isDisabled );\n
\t\t}\n
\t\tif ( this.type === "radio" ) {\n
\t\t\tradioGroup( this.element[0] ).each(function() {\n
\t\t\t\tif ( $( this ).is( ":checked" ) ) {\n
\t\t\t\t\t$( this ).button( "widget" )\n
\t\t\t\t\t\t.addClass( "ui-state-active" )\n
\t\t\t\t\t\t.attr( "aria-pressed", true );\n
\t\t\t\t} else {\n
\t\t\t\t\t$( this ).button( "widget" )\n
\t\t\t\t\t\t.removeClass( "ui-state-active" )\n
\t\t\t\t\t\t.attr( "aria-pressed", false );\n
\t\t\t\t}\n
\t\t\t});\n
\t\t} else if ( this.type === "checkbox" ) {\n
\t\t\tif ( this.element.is( ":checked" ) ) {\n
\t\t\t\tthis.buttonElement\n
\t\t\t\t\t.addClass( "ui-state-active" )\n
\t\t\t\t\t.attr( "aria-pressed", true );\n
\t\t\t} else {\n
\t\t\t\tthis.buttonElement\n
\t\t\t\t\t.removeClass( "ui-state-active" )\n
\t\t\t\t\t.attr( "aria-pressed", false );\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t_resetButton: function() {\n
\t\tif ( this.type === "input" ) {\n
\t\t\tif ( this.options.label ) {\n
\t\t\t\tthis.element.val( this.options.label );\n
\t\t\t}\n
\t\t\treturn;\n
\t\t}\n
\t\tvar buttonElement = this.buttonElement.removeClass( typeClasses ),\n
\t\t\tbuttonText = $( "<span></span>" )\n
\t\t\t\t.addClass( "ui-button-text" )\n
\t\t\t\t.html( this.options.label )\n
\t\t\t\t.appendTo( buttonElement.empty() )\n
\t\t\t\t.text(),\n
\t\t\ticons = this.options.icons,\n
\t\t\tmultipleIcons = icons.primary && icons.secondary;\n
\t\tif ( icons.primary || icons.secondary ) {\n
\t\t\tbuttonElement.addClass( "ui-button-text-icon" +\n
\t\t\t\t( multipleIcons ? "s" : "" ) );\n
\t\t\tif ( icons.primary ) {\n
\t\t\t\tbuttonElement.prepend( "<span class=\'ui-button-icon-primary ui-icon " + icons.primary + "\'></span>" );\n
\t\t\t}\n
\t\t\tif ( icons.secondary ) {\n
\t\t\t\tbuttonElement.append( "<span class=\'ui-button-icon-secondary ui-icon " + icons.secondary + "\'></span>" );\n
\t\t\t}\n
\t\t\tif ( !this.options.text ) {\n
\t\t\t\tbuttonElement\n
\t\t\t\t\t.addClass( multipleIcons ? "ui-button-icons-only" : "ui-button-icon-only" )\n
\t\t\t\t\t.removeClass( "ui-button-text-icons ui-button-text-icon" );\n
\t\t\t\tif ( !this.hasTitle ) {\n
\t\t\t\t\tbuttonElement.attr( "title", buttonText );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t} else {\n
\t\t\tbuttonElement.addClass( "ui-button-text-only" );\n
\t\t}\n
\t}\n
});\n
\n
$.widget( "ui.buttonset", {\n
\t_create: function() {\n
\t\tthis.element.addClass( "ui-buttonset" );\n
\t\tthis._init();\n
\t},\n
\t\n
\t_init: function() {\n
\t\tthis.refresh();\n
\t},\n
\n
\t_setOption: function( key, value ) {\n
\t\tif ( key === "disabled" ) {\n
\t\t\tthis.buttons.button( "option", key, value );\n
\t\t}\n
\n
\t\t$.Widget.prototype._setOption.apply( this, arguments );\n
\t},\n
\t\n
\trefresh: function() {\n
\t\tthis.buttons = this.element.find( ":button, :submit, :reset, :checkbox, :radio, a, :data(button)" )\n
\t\t\t.filter( ":ui-button" )\n
\t\t\t\t.button( "refresh" )\n
\t\t\t.end()\n
\t\t\t.not( ":ui-button" )\n
\t\t\t\t.button()\n
\t\t\t.end()\n
\t\t\t.map(function() {\n
\t\t\t\treturn $( this ).button( "widget" )[ 0 ];\n
\t\t\t})\n
\t\t\t\t.removeClass( "ui-corner-all ui-corner-left ui-corner-right" )\n
\t\t\t\t.filter( ":first" )\n
\t\t\t\t\t.addClass( "ui-corner-left" )\n
\t\t\t\t.end()\n
\t\t\t\t.filter( ":last" )\n
\t\t\t\t\t.addClass( "ui-corner-right" )\n
\t\t\t\t.end()\n
\t\t\t.end();\n
\t},\n
\n
\tdestroy: function() {\n
\t\tthis.element.removeClass( "ui-buttonset" );\n
\t\tthis.buttons\n
\t\t\t.map(function() {\n
\t\t\t\treturn $( this ).button( "widget" )[ 0 ];\n
\t\t\t})\n
\t\t\t\t.removeClass( "ui-corner-left ui-corner-right" )\n
\t\t\t.end()\n
\t\t\t.button( "destroy" );\n
\n
\t\t$.Widget.prototype.destroy.call( this );\n
\t}\n
});\n
\n
}( jQuery ) );\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>9638</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
