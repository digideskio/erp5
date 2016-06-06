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
            <value> <string>ts63969427.42</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>validate.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*!\n
 * jQuery Validation Plugin 1.11.1\n
 *\n
 * http://bassistance.de/jquery-plugins/jquery-plugin-validation/\n
 * http://docs.jquery.com/Plugins/Validation\n
 *\n
 * Copyright 2013 Jörn Zaefferer\n
 * Released under the MIT license:\n
 *   http://www.opensource.org/licenses/mit-license.php\n
 */\n
\n
(function($) {\n
\n
$.extend($.fn, {\n
\t// http://docs.jquery.com/Plugins/Validation/validate\n
\tvalidate: function( options ) {\n
\n
\t\t// if nothing is selected, return nothing; can\'t chain anyway\n
\t\tif ( !this.length ) {\n
\t\t\tif ( options && options.debug && window.console ) {\n
\t\t\t\tconsole.warn( "Nothing selected, can\'t validate, returning nothing." );\n
\t\t\t}\n
\t\t\treturn;\n
\t\t}\n
\n
\t\t// check if a validator for this form was already created\n
\t\tvar validator = $.data( this[0], "validator" );\n
\t\tif ( validator ) {\n
\t\t\treturn validator;\n
\t\t}\n
\n
\t\t// Add novalidate tag if HTML5.\n
\t\tthis.attr( "novalidate", "novalidate" );\n
\n
\t\tvalidator = new $.validator( options, this[0] );\n
\t\t$.data( this[0], "validator", validator );\n
\n
\t\tif ( validator.settings.onsubmit ) {\n
\n
\t\t\tthis.validateDelegate( ":submit", "click", function( event ) {\n
\t\t\t\tif ( validator.settings.submitHandler ) {\n
\t\t\t\t\tvalidator.submitButton = event.target;\n
\t\t\t\t}\n
\t\t\t\t// allow suppressing validation by adding a cancel class to the submit button\n
\t\t\t\tif ( $(event.target).hasClass("cancel") ) {\n
\t\t\t\t\tvalidator.cancelSubmit = true;\n
\t\t\t\t}\n
\n
\t\t\t\t// allow suppressing validation by adding the html5 formnovalidate attribute to the submit button\n
\t\t\t\tif ( $(event.target).attr("formnovalidate") !== undefined ) {\n
\t\t\t\t\tvalidator.cancelSubmit = true;\n
\t\t\t\t}\n
\t\t\t});\n
\n
\t\t\t// validate the form on submit\n
\t\t\tthis.submit( function( event ) {\n
\t\t\t\tif ( validator.settings.debug ) {\n
\t\t\t\t\t// prevent form submit to be able to see console output\n
\t\t\t\t\tevent.preventDefault();\n
\t\t\t\t}\n
\t\t\t\tfunction handle() {\n
\t\t\t\t\tvar hidden;\n
\t\t\t\t\tif ( validator.settings.submitHandler ) {\n
\t\t\t\t\t\tif ( validator.submitButton ) {\n
\t\t\t\t\t\t\t// insert a hidden input as a replacement for the missing submit button\n
\t\t\t\t\t\t\thidden = $("<input type=\'hidden\'/>").attr("name", validator.submitButton.name).val( $(validator.submitButton).val() ).appendTo(validator.currentForm);\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tvalidator.settings.submitHandler.call( validator, validator.currentForm, event );\n
\t\t\t\t\t\tif ( validator.submitButton ) {\n
\t\t\t\t\t\t\t// and clean up afterwards; thanks to no-block-scope, hidden can be referenced\n
\t\t\t\t\t\t\thidden.remove();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t\treturn true;\n
\t\t\t\t}\n
\n
\t\t\t\t// prevent submit for invalid forms or custom submit handlers\n
\t\t\t\tif ( validator.cancelSubmit ) {\n
\t\t\t\t\tvalidator.cancelSubmit = false;\n
\t\t\t\t\treturn handle();\n
\t\t\t\t}\n
\t\t\t\tif ( validator.form() ) {\n
\t\t\t\t\tif ( validator.pendingRequest ) {\n
\t\t\t\t\t\tvalidator.formSubmitted = true;\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t\treturn handle();\n
\t\t\t\t} else {\n
\t\t\t\t\tvalidator.focusInvalid();\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t});\n
\t\t}\n
\n
\t\treturn validator;\n
\t},\n
\t// http://docs.jquery.com/Plugins/Validation/valid\n
\tvalid: function() {\n
\t\tif ( $(this[0]).is("form")) {\n
\t\t\treturn this.validate().form();\n
\t\t} else {\n
\t\t\tvar valid = true;\n
\t\t\tvar validator = $(this[0].form).validate();\n
\t\t\tthis.each(function() {\n
\t\t\t\tvalid = valid && validator.element(this);\n
\t\t\t});\n
\t\t\treturn valid;\n
\t\t}\n
\t},\n
\t// attributes: space seperated list of attributes to retrieve and remove\n
\tremoveAttrs: function( attributes ) {\n
\t\tvar result = {},\n
\t\t\t$element = this;\n
\t\t$.each(attributes.split(/\\s/), function( index, value ) {\n
\t\t\tresult[value] = $element.attr(value);\n
\t\t\t$element.removeAttr(value);\n
\t\t});\n
\t\treturn result;\n
\t},\n
\t// http://docs.jquery.com/Plugins/Validation/rules\n
\trules: function( command, argument ) {\n
\t\tvar element = this[0];\n
\n
\t\tif ( command ) {\n
\t\t\tvar settings = $.data(element.form, "validator").settings;\n
\t\t\tvar staticRules = settings.rules;\n
\t\t\tvar existingRules = $.validator.staticRules(element);\n
\t\t\tswitch(command) {\n
\t\t\tcase "add":\n
\t\t\t\t$.extend(existingRules, $.validator.normalizeRule(argument));\n
\t\t\t\t// remove messages from rules, but allow them to be set separetely\n
\t\t\t\tdelete existingRules.messages;\n
\t\t\t\tstaticRules[element.name] = existingRules;\n
\t\t\t\tif ( argument.messages ) {\n
\t\t\t\t\tsettings.messages[element.name] = $.extend( settings.messages[element.name], argument.messages );\n
\t\t\t\t}\n
\t\t\t\tbreak;\n
\t\t\tcase "remove":\n
\t\t\t\tif ( !argument ) {\n
\t\t\t\t\tdelete staticRules[element.name];\n
\t\t\t\t\treturn existingRules;\n
\t\t\t\t}\n
\t\t\t\tvar filtered = {};\n
\t\t\t\t$.each(argument.split(/\\s/), function( index, method ) {\n
\t\t\t\t\tfiltered[method] = existingRules[method];\n
\t\t\t\t\tdelete existingRules[method];\n
\t\t\t\t});\n
\t\t\t\treturn filtered;\n
\t\t\t}\n
\t\t}\n
\n
\t\tvar data = $.validator.normalizeRules(\n
\t\t$.extend(\n
\t\t\t{},\n
\t\t\t$.validator.classRules(element),\n
\t\t\t$.validator.attributeRules(element),\n
\t\t\t$.validator.dataRules(element),\n
\t\t\t$.validator.staticRules(element)\n
\t\t), element);\n
\n
\t\t// make sure required is at front\n
\t\tif ( data.required ) {\n
\t\t\tvar param = data.required;\n
\t\t\tdelete data.required;\n
\t\t\tdata = $.extend({required: param}, data);\n
\t\t}\n
\n
\t\treturn data;\n
\t}\n
});\n
\n
// Custom selectors\n
$.extend($.expr[":"], {\n
\t// http://docs.jquery.com/Plugins/Validation/blank\n
\tblank: function( a ) { return !$.trim("" + $(a).val()); },\n
\t// http://docs.jquery.com/Plugins/Validation/filled\n
\tfilled: function( a ) { return !!$.trim("" + $(a).val()); },\n
\t// http://docs.jquery.com/Plugins/Validation/unchecked\n
\tunchecked: function( a ) { return !$(a).prop("checked"); }\n
});\n
\n
// constructor for validator\n
$.validator = function( options, form ) {\n
\tthis.settings = $.extend( true, {}, $.validator.defaults, options );\n
\tthis.currentForm = form;\n
\tthis.init();\n
};\n
\n
$.validator.format = function( source, params ) {\n
\tif ( arguments.length === 1 ) {\n
\t\treturn function() {\n
\t\t\tvar args = $.makeArray(arguments);\n
\t\t\targs.unshift(source);\n
\t\t\treturn $.validator.format.apply( this, args );\n
\t\t};\n
\t}\n
\tif ( arguments.length > 2 && params.constructor !== Array  ) {\n
\t\tparams = $.makeArray(arguments).slice(1);\n
\t}\n
\tif ( params.constructor !== Array ) {\n
\t\tparams = [ params ];\n
\t}\n
\t$.each(params, function( i, n ) {\n
\t\tsource = source.replace( new RegExp("\\\\{" + i + "\\\\}", "g"), function() {\n
\t\t\treturn n;\n
\t\t});\n
\t});\n
\treturn source;\n
};\n
\n
$.extend($.validator, {\n
\n
\tdefaults: {\n
\t\tmessages: {},\n
\t\tgroups: {},\n
\t\trules: {},\n
\t\terrorClass: "error",\n
\t\tvalidClass: "valid",\n
\t\terrorElement: "label",\n
\t\tfocusInvalid: true,\n
\t\terrorContainer: $([]),\n
\t\terrorLabelContainer: $([]),\n
\t\tonsubmit: true,\n
\t\tignore: ":hidden",\n
\t\tignoreTitle: false,\n
\t\tonfocusin: function( element, event ) {\n
\t\t\tthis.lastActive = element;\n
\n
\t\t\t// hide error label and remove error class on focus if enabled\n
\t\t\tif ( this.settings.focusCleanup && !this.blockFocusCleanup ) {\n
\t\t\t\tif ( this.settings.unhighlight ) {\n
\t\t\t\t\tthis.settings.unhighlight.call( this, element, this.settings.errorClass, this.settings.validClass );\n
\t\t\t\t}\n
\t\t\t\tthis.addWrapper(this.errorsFor(element)).hide();\n
\t\t\t}\n
\t\t},\n
\t\tonfocusout: function( element, event ) {\n
\t\t\tif ( !this.checkable(element) && (element.name in this.submitted || !this.optional(element)) ) {\n
\t\t\t\tthis.element(element);\n
\t\t\t}\n
\t\t},\n
\t\tonkeyup: function( element, event ) {\n
\t\t\tif ( event.which === 9 && this.elementValue(element) === "" ) {\n
\t\t\t\treturn;\n
\t\t\t} else if ( element.name in this.submitted || element === this.lastElement ) {\n
\t\t\t\tthis.element(element);\n
\t\t\t}\n
\t\t},\n
\t\tonclick: function( element, event ) {\n
\t\t\t// click on selects, radiobuttons and checkboxes\n
\t\t\tif ( element.name in this.submitted ) {\n
\t\t\t\tthis.element(element);\n
\t\t\t}\n
\t\t\t// or option elements, check parent select in that case\n
\t\t\telse if ( element.parentNode.name in this.submitted ) {\n
\t\t\t\tthis.element(element.parentNode);\n
\t\t\t}\n
\t\t},\n
\t\thighlight: function( element, errorClass, validClass ) {\n
\t\t\tif ( element.type === "radio" ) {\n
\t\t\t\tthis.findByName(element.name).addClass(errorClass).removeClass(validClass);\n
\t\t\t} else {\n
\t\t\t\t$(element).addClass(errorClass).removeClass(validClass);\n
\t\t\t}\n
\t\t},\n
\t\tunhighlight: function( element, errorClass, validClass ) {\n
\t\t\tif ( element.type === "radio" ) {\n
\t\t\t\tthis.findByName(element.name).removeClass(errorClass).addClass(validClass);\n
\t\t\t} else {\n
\t\t\t\t$(element).removeClass(errorClass).addClass(validClass);\n
\t\t\t}\n
\t\t}\n
\t},\n
\n
\t// http://docs.jquery.com/Plugins/Validation/Validator/setDefaults\n
\tsetDefaults: function( settings ) {\n
\t\t$.extend( $.validator.defaults, settings );\n
\t},\n
\n
\tmessages: {\n
\t\trequired: "This field is required.",\n
\t\tremote: "Please fix this field.",\n
\t\temail: "Please enter a valid email address.",\n
\t\turl: "Please enter a valid URL.",\n
\t\tdate: "Please enter a valid date.",\n
\t\tdateISO: "Please enter a valid date (ISO).",\n
\t\tnumber: "Please enter a valid number.",\n
\t\tdigits: "Please enter only digits.",\n
\t\tcreditcard: "Please enter a valid credit card number.",\n
\t\tequalTo: "Please enter the same value again.",\n
\t\tmaxlength: $.validator.format("Please enter no more than {0} characters."),\n
\t\tminlength: $.validator.format("Please enter at least {0} characters."),\n
\t\trangelength: $.validator.format("Please enter a value between {0} and {1} characters long."),\n
\t\trange: $.validator.format("Please enter a value between {0} and {1}."),\n
\t\tmax: $.validator.format("Please enter a value less than or equal to {0}."),\n
\t\tmin: $.validator.format("Please enter a value greater than or equal to {0}.")\n
\t},\n
\n
\tautoCreateRanges: false,\n
\n
\tprototype: {\n
\n
\t\tinit: function() {\n
\t\t\tthis.labelContainer = $(this.settings.errorLabelContainer);\n
\t\t\tthis.errorContext = this.labelContainer.length && this.labelContainer || $(this.currentForm);\n
\t\t\tthis.containers = $(this.settings.errorContainer).add( this.settings.errorLabelContainer );\n
\t\t\tthis.submitted = {};\n
\t\t\tthis.valueCache = {};\n
\t\t\tthis.pendingRequest = 0;\n
\t\t\tthis.pending = {};\n
\t\t\tthis.invalid = {};\n
\t\t\tthis.reset();\n
\n
\t\t\tvar groups = (this.groups = {});\n
\t\t\t$.each(this.settings.groups, function( key, value ) {\n
\t\t\t\tif ( typeof value === "string" ) {\n
\t\t\t\t\tvalue = value.split(/\\s/);\n
\t\t\t\t}\n
\t\t\t\t$.each(value, function( index, name ) {\n
\t\t\t\t\tgroups[name] = key;\n
\t\t\t\t});\n
\t\t\t});\n
\t\t\tvar rules = this.settings.rules;\n
\t\t\t$.each(rules, function( key, value ) {\n
\t\t\t\trules[key] = $.validator.normalizeRule(value);\n
\t\t\t});\n
\n
\t\t\tfunction delegate(event) {\n
\t\t\t\tvar validator = $.data(this[0].form, "validator"),\n
\t\t\t\t\teventType = "on" + event.type.replace(/^validate/, "");\n
\t\t\t\tif ( validator.settings[eventType] ) {\n
\t\t\t\t\tvalidator.settings[eventType].call(validator, this[0], event);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\t$(this.currentForm)\n
\t\t\t\t.validateDelegate(":text, [type=\'password\'], [type=\'file\'], select, textarea, " +\n
\t\t\t\t\t"[type=\'number\'], [type=\'search\'] ,[type=\'tel\'], [type=\'url\'], " +\n
\t\t\t\t\t"[type=\'email\'], [type=\'datetime\'], [type=\'date\'], [type=\'month\'], " +\n
\t\t\t\t\t"[type=\'week\'], [type=\'time\'], [type=\'datetime-local\'], " +\n
\t\t\t\t\t"[type=\'range\'], [type=\'color\'] ",\n
\t\t\t\t\t"focusin focusout keyup", delegate)\n
\t\t\t\t.validateDelegate("[type=\'radio\'], [type=\'checkbox\'], select, option", "click", delegate);\n
\n
\t\t\tif ( this.settings.invalidHandler ) {\n
\t\t\t\t$(this.currentForm).bind("invalid-form.validate", this.settings.invalidHandler);\n
\t\t\t}\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Validator/form\n
\t\tform: function() {\n
\t\t\tthis.checkForm();\n
\t\t\t$.extend(this.submitted, this.errorMap);\n
\t\t\tthis.invalid = $.extend({}, this.errorMap);\n
\t\t\tif ( !this.valid() ) {\n
\t\t\t\t$(this.currentForm).triggerHandler("invalid-form", [this]);\n
\t\t\t}\n
\t\t\tthis.showErrors();\n
\t\t\treturn this.valid();\n
\t\t},\n
\n
\t\tcheckForm: function() {\n
\t\t\tthis.prepareForm();\n
\t\t\tfor ( var i = 0, elements = (this.currentElements = this.elements()); elements[i]; i++ ) {\n
\t\t\t\tthis.check( elements[i] );\n
\t\t\t}\n
\t\t\treturn this.valid();\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Validator/element\n
\t\telement: function( element ) {\n
\t\t\telement = this.validationTargetFor( this.clean( element ) );\n
\t\t\tthis.lastElement = element;\n
\t\t\tthis.prepareElement( element );\n
\t\t\tthis.currentElements = $(element);\n
\t\t\tvar result = this.check( element ) !== false;\n
\t\t\tif ( result ) {\n
\t\t\t\tdelete this.invalid[element.name];\n
\t\t\t} else {\n
\t\t\t\tthis.invalid[element.name] = true;\n
\t\t\t}\n
\t\t\tif ( !this.numberOfInvalids() ) {\n
\t\t\t\t// Hide error containers on last error\n
\t\t\t\tthis.toHide = this.toHide.add( this.containers );\n
\t\t\t}\n
\t\t\tthis.showErrors();\n
\t\t\treturn result;\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Validator/showErrors\n
\t\tshowErrors: function( errors ) {\n
\t\t\tif ( errors ) {\n
\t\t\t\t// add items to error list and map\n
\t\t\t\t$.extend( this.errorMap, errors );\n
\t\t\t\tthis.errorList = [];\n
\t\t\t\tfor ( var name in errors ) {\n
\t\t\t\t\tthis.errorList.push({\n
\t\t\t\t\t\tmessage: errors[name],\n
\t\t\t\t\t\telement: this.findByName(name)[0]\n
\t\t\t\t\t});\n
\t\t\t\t}\n
\t\t\t\t// remove items from success list\n
\t\t\t\tthis.successList = $.grep( this.successList, function( element ) {\n
\t\t\t\t\treturn !(element.name in errors);\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\tif ( this.settings.showErrors ) {\n
\t\t\t\tthis.settings.showErrors.call( this, this.errorMap, this.errorList );\n
\t\t\t} else {\n
\t\t\t\tthis.defaultShowErrors();\n
\t\t\t}\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Validator/resetForm\n
\t\tresetForm: function() {\n
\t\t\tif ( $.fn.resetForm ) {\n
\t\t\t\t$(this.currentForm).resetForm();\n
\t\t\t}\n
\t\t\tthis.submitted = {};\n
\t\t\tthis.lastElement = null;\n
\t\t\tthis.prepareForm();\n
\t\t\tthis.hideErrors();\n
\t\t\tthis.elements().removeClass( this.settings.errorClass ).removeData( "previousValue" );\n
\t\t},\n
\n
\t\tnumberOfInvalids: function() {\n
\t\t\treturn this.objectLength(this.invalid);\n
\t\t},\n
\n
\t\tobjectLength: function( obj ) {\n
\t\t\tvar count = 0;\n
\t\t\tfor ( var i in obj ) {\n
\t\t\t\tcount++;\n
\t\t\t}\n
\t\t\treturn count;\n
\t\t},\n
\n
\t\thideErrors: function() {\n
\t\t\tthis.addWrapper( this.toHide ).hide();\n
\t\t},\n
\n
\t\tvalid: function() {\n
\t\t\treturn this.size() === 0;\n
\t\t},\n
\n
\t\tsize: function() {\n
\t\t\treturn this.errorList.length;\n
\t\t},\n
\n
\t\tfocusInvalid: function() {\n
\t\t\tif ( this.settings.focusInvalid ) {\n
\t\t\t\ttry {\n
\t\t\t\t\t$(this.findLastActive() || this.errorList.length && this.errorList[0].element || [])\n
\t\t\t\t\t.filter(":visible")\n
\t\t\t\t\t.focus()\n
\t\t\t\t\t// manually trigger focusin event; without it, focusin handler isn\'t called, findLastActive won\'t have anything to find\n
\t\t\t\t\t.trigger("focusin");\n
\t\t\t\t} catch(e) {\n
\t\t\t\t\t// ignore IE throwing errors when focusing hidden elements\n
\t\t\t\t}\n
\t\t\t}\n
\t\t},\n
\n
\t\tfindLastActive: function() {\n
\t\t\tvar lastActive = this.lastActive;\n
\t\t\treturn lastActive && $.grep(this.errorList, function( n ) {\n
\t\t\t\treturn n.element.name === lastActive.name;\n
\t\t\t}).length === 1 && lastActive;\n
\t\t},\n
\n
\t\telements: function() {\n
\t\t\tvar validator = this,\n
\t\t\t\trulesCache = {};\n
\n
\t\t\t// select all valid inputs inside the form (no submit or reset buttons)\n
\t\t\treturn $(this.currentForm)\n
\t\t\t.find("input, select, textarea")\n
\t\t\t.not(":submit, :reset, :image, [disabled]")\n
\t\t\t.not( this.settings.ignore )\n
\t\t\t.filter(function() {\n
\t\t\t\tif ( !this.name && validator.settings.debug && window.console ) {\n
\t\t\t\t\tconsole.error( "%o has no name assigned", this);\n
\t\t\t\t}\n
\n
\t\t\t\t// select only the first element for each name, and only those with rules specified\n
\t\t\t\tif ( this.name in rulesCache || !validator.objectLength($(this).rules()) ) {\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\n
\t\t\t\trulesCache[this.name] = true;\n
\t\t\t\treturn true;\n
\t\t\t});\n
\t\t},\n
\n
\t\tclean: function( selector ) {\n
\t\t\treturn $(selector)[0];\n
\t\t},\n
\n
\t\terrors: function() {\n
\t\t\tvar errorClass = this.settings.errorClass.replace(" ", ".");\n
\t\t\treturn $(this.settings.errorElement + "." + errorClass, this.errorContext);\n
\t\t},\n
\n
\t\treset: function() {\n
\t\t\tthis.successList = [];\n
\t\t\tthis.errorList = [];\n
\t\t\tthis.errorMap = {};\n
\t\t\tthis.toShow = $([]);\n
\t\t\tthis.toHide = $([]);\n
\t\t\tthis.currentElements = $([]);\n
\t\t},\n
\n
\t\tprepareForm: function() {\n
\t\t\tthis.reset();\n
\t\t\tthis.toHide = this.errors().add( this.containers );\n
\t\t},\n
\n
\t\tprepareElement: function( element ) {\n
\t\t\tthis.reset();\n
\t\t\tthis.toHide = this.errorsFor(element);\n
\t\t},\n
\n
\t\telementValue: function( element ) {\n
\t\t\tvar type = $(element).attr("type"),\n
\t\t\t\tval = $(element).val();\n
\n
\t\t\tif ( type === "radio" || type === "checkbox" ) {\n
\t\t\t\treturn $("input[name=\'" + $(element).attr("name") + "\']:checked").val();\n
\t\t\t}\n
\n
\t\t\tif ( typeof val === "string" ) {\n
\t\t\t\treturn val.replace(/\\r/g, "");\n
\t\t\t}\n
\t\t\treturn val;\n
\t\t},\n
\n
\t\tcheck: function( element ) {\n
\t\t\telement = this.validationTargetFor( this.clean( element ) );\n
\n
\t\t\tvar rules = $(element).rules();\n
\t\t\tvar dependencyMismatch = false;\n
\t\t\tvar val = this.elementValue(element);\n
\t\t\tvar result;\n
\n
\t\t\tfor (var method in rules ) {\n
\t\t\t\tvar rule = { method: method, parameters: rules[method] };\n
\t\t\t\ttry {\n
\n
\t\t\t\t\tresult = $.validator.methods[method].call( this, val, element, rule.parameters );\n
\n
\t\t\t\t\t// if a method indicates that the field is optional and therefore valid,\n
\t\t\t\t\t// don\'t mark it as valid when there are no other rules\n
\t\t\t\t\tif ( result === "dependency-mismatch" ) {\n
\t\t\t\t\t\tdependencyMismatch = true;\n
\t\t\t\t\t\tcontinue;\n
\t\t\t\t\t}\n
\t\t\t\t\tdependencyMismatch = false;\n
\n
\t\t\t\t\tif ( result === "pending" ) {\n
\t\t\t\t\t\tthis.toHide = this.toHide.not( this.errorsFor(element) );\n
\t\t\t\t\t\treturn;\n
\t\t\t\t\t}\n
\n
\t\t\t\t\tif ( !result ) {\n
\t\t\t\t\t\tthis.formatAndAdd( element, rule );\n
\t\t\t\t\t\treturn false;\n
\t\t\t\t\t}\n
\t\t\t\t} catch(e) {\n
\t\t\t\t\tif ( this.settings.debug && window.console ) {\n
\t\t\t\t\t\tconsole.log( "Exception occurred when checking element " + element.id + ", check the \'" + rule.method + "\' method.", e );\n
\t\t\t\t\t}\n
\t\t\t\t\tthrow e;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tif ( dependencyMismatch ) {\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tif ( this.objectLength(rules) ) {\n
\t\t\t\tthis.successList.push(element);\n
\t\t\t}\n
\t\t\treturn true;\n
\t\t},\n
\n
\t\t// return the custom message for the given element and validation method\n
\t\t// specified in the element\'s HTML5 data attribute\n
\t\tcustomDataMessage: function( element, method ) {\n
\t\t\treturn $(element).data("msg-" + method.toLowerCase()) || (element.attributes && $(element).attr("data-msg-" + method.toLowerCase()));\n
\t\t},\n
\n
\t\t// return the custom message for the given element name and validation method\n
\t\tcustomMessage: function( name, method ) {\n
\t\t\tvar m = this.settings.messages[name];\n
\t\t\treturn m && (m.constructor === String ? m : m[method]);\n
\t\t},\n
\n
\t\t// return the first defined argument, allowing empty strings\n
\t\tfindDefined: function() {\n
\t\t\tfor(var i = 0; i < arguments.length; i++) {\n
\t\t\t\tif ( arguments[i] !== undefined ) {\n
\t\t\t\t\treturn arguments[i];\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn undefined;\n
\t\t},\n
\n
\t\tdefaultMessage: function( element, method ) {\n
\t\t\treturn this.findDefined(\n
\t\t\t\tthis.customMessage( element.name, method ),\n
\t\t\t\tthis.customDataMessage( element, method ),\n
\t\t\t\t// title is never undefined, so handle empty string as undefined\n
\t\t\t\t!this.settings.ignoreTitle && element.title || undefined,\n
\t\t\t\t$.validator.messages[method],\n
\t\t\t\t"<strong>Warning: No message defined for " + element.name + "</strong>"\n
\t\t\t);\n
\t\t},\n
\n
\t\tformatAndAdd: function( element, rule ) {\n
\t\t\tvar message = this.defaultMessage( element, rule.method ),\n
\t\t\t\ttheregex = /\\$?\\{(\\d+)\\}/g;\n
\t\t\tif ( typeof message === "function" ) {\n
\t\t\t\tmessage = message.call(this, rule.parameters, element);\n
\t\t\t} else if (theregex.test(message)) {\n
\t\t\t\tmessage = $.validator.format(message.replace(theregex, "{$1}"), rule.parameters);\n
\t\t\t}\n
\t\t\tthis.errorList.push({\n
\t\t\t\tmessage: message,\n
\t\t\t\telement: element\n
\t\t\t});\n
\n
\t\t\tthis.errorMap[element.name] = message;\n
\t\t\tthis.submitted[element.name] = message;\n
\t\t},\n
\n
\t\taddWrapper: function( toToggle ) {\n
\t\t\tif ( this.settings.wrapper ) {\n
\t\t\t\ttoToggle = toToggle.add( toToggle.parent( this.settings.wrapper ) );\n
\t\t\t}\n
\t\t\treturn toToggle;\n
\t\t},\n
\n
\t\tdefaultShowErrors: function() {\n
\t\t\tvar i, elements;\n
\t\t\tfor ( i = 0; this.errorList[i]; i++ ) {\n
\t\t\t\tvar error = this.errorList[i];\n
\t\t\t\tif ( this.settings.highlight ) {\n
\t\t\t\t\tthis.settings.highlight.call( this, error.element, this.settings.errorClass, this.settings.validClass );\n
\t\t\t\t}\n
\t\t\t\tthis.showLabel( error.element, error.message );\n
\t\t\t}\n
\t\t\tif ( this.errorList.length ) {\n
\t\t\t\tthis.toShow = this.toShow.add( this.containers );\n
\t\t\t}\n
\t\t\tif ( this.settings.success ) {\n
\t\t\t\tfor ( i = 0; this.successList[i]; i++ ) {\n
\t\t\t\t\tthis.showLabel( this.successList[i] );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tif ( this.settings.unhighlight ) {\n
\t\t\t\tfor ( i = 0, elements = this.validElements(); elements[i]; i++ ) {\n
\t\t\t\t\tthis.settings.unhighlight.call( this, elements[i], this.settings.errorClass, this.settings.validClass );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tthis.toHide = this.toHide.not( this.toShow );\n
\t\t\tthis.hideErrors();\n
\t\t\tthis.addWrapper( this.toShow ).show();\n
\t\t},\n
\n
\t\tvalidElements: function() {\n
\t\t\treturn this.currentElements.not(this.invalidElements());\n
\t\t},\n
\n
\t\tinvalidElements: function() {\n
\t\t\treturn $(this.errorList).map(function() {\n
\t\t\t\treturn this.element;\n
\t\t\t});\n
\t\t},\n
\n
\t\tshowLabel: function( element, message ) {\n
\t\t\tvar label = this.errorsFor( element );\n
\t\t\tif ( label.length ) {\n
\t\t\t\t// refresh error/success class\n
\t\t\t\tlabel.removeClass( this.settings.validClass ).addClass( this.settings.errorClass );\n
\t\t\t\t// replace message on existing label\n
\t\t\t\tlabel.html(message);\n
\t\t\t} else {\n
\t\t\t\t// create label\n
\t\t\t\tlabel = $("<" + this.settings.errorElement + ">")\n
\t\t\t\t\t.attr("for", this.idOrName(element))\n
\t\t\t\t\t.addClass(this.settings.errorClass)\n
\t\t\t\t\t.html(message || "");\n
\t\t\t\tif ( this.settings.wrapper ) {\n
\t\t\t\t\t// make sure the element is visible, even in IE\n
\t\t\t\t\t// actually showing the wrapped element is handled elsewhere\n
\t\t\t\t\tlabel = label.hide().show().wrap("<" + this.settings.wrapper + "/>").parent();\n
\t\t\t\t}\n
\t\t\t\tif ( !this.labelContainer.append(label).length ) {\n
\t\t\t\t\tif ( this.settings.errorPlacement ) {\n
\t\t\t\t\t\tthis.settings.errorPlacement(label, $(element) );\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tlabel.insertAfter(element);\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tif ( !message && this.settings.success ) {\n
\t\t\t\tlabel.text("");\n
\t\t\t\tif ( typeof this.settings.success === "string" ) {\n
\t\t\t\t\tlabel.addClass( this.settings.success );\n
\t\t\t\t} else {\n
\t\t\t\t\tthis.settings.success( label, element );\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\tthis.toShow = this.toShow.add(label);\n
\t\t},\n
\n
\t\terrorsFor: function( element ) {\n
\t\t\tvar name = this.idOrName(element);\n
\t\t\treturn this.errors().filter(function() {\n
\t\t\t\treturn $(this).attr("for") === name;\n
\t\t\t});\n
\t\t},\n
\n
\t\tidOrName: function( element ) {\n
\t\t\treturn this.groups[element.name] || (this.checkable(element) ? element.name : element.id || element.name);\n
\t\t},\n
\n
\t\tvalidationTargetFor: function( element ) {\n
\t\t\t// if radio/checkbox, validate first element in group instead\n
\t\t\tif ( this.checkable(element) ) {\n
\t\t\t\telement = this.findByName( element.name ).not(this.settings.ignore)[0];\n
\t\t\t}\n
\t\t\treturn element;\n
\t\t},\n
\n
\t\tcheckable: function( element ) {\n
\t\t\treturn (/radio|checkbox/i).test(element.type);\n
\t\t},\n
\n
\t\tfindByName: function( name ) {\n
\t\t\treturn $(this.currentForm).find("[name=\'" + name + "\']");\n
\t\t},\n
\n
\t\tgetLength: function( value, element ) {\n
\t\t\tswitch( element.nodeName.toLowerCase() ) {\n
\t\t\tcase "select":\n
\t\t\t\treturn $("option:selected", element).length;\n
\t\t\tcase "input":\n
\t\t\t\tif ( this.checkable( element) ) {\n
\t\t\t\t\treturn this.findByName(element.name).filter(":checked").length;\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn value.length;\n
\t\t},\n
\n
\t\tdepend: function( param, element ) {\n
\t\t\treturn this.dependTypes[typeof param] ? this.dependTypes[typeof param](param, element) : true;\n
\t\t},\n
\n
\t\tdependTypes: {\n
\t\t\t"boolean": function( param, element ) {\n
\t\t\t\treturn param;\n
\t\t\t},\n
\t\t\t"string": function( param, element ) {\n
\t\t\t\treturn !!$(param, element.form).length;\n
\t\t\t},\n
\t\t\t"function": function( param, element ) {\n
\t\t\t\treturn param(element);\n
\t\t\t}\n
\t\t},\n
\n
\t\toptional: function( element ) {\n
\t\t\tvar val = this.elementValue(element);\n
\t\t\treturn !$.validator.methods.required.call(this, val, element) && "dependency-mismatch";\n
\t\t},\n
\n
\t\tstartRequest: function( element ) {\n
\t\t\tif ( !this.pending[element.name] ) {\n
\t\t\t\tthis.pendingRequest++;\n
\t\t\t\tthis.pending[element.name] = true;\n
\t\t\t}\n
\t\t},\n
\n
\t\tstopRequest: function( element, valid ) {\n
\t\t\tthis.pendingRequest--;\n
\t\t\t// sometimes synchronization fails, make sure pendingRequest is never < 0\n
\t\t\tif ( this.pendingRequest < 0 ) {\n
\t\t\t\tthis.pendingRequest = 0;\n
\t\t\t}\n
\t\t\tdelete this.pending[element.name];\n
\t\t\tif ( valid && this.pendingRequest === 0 && this.formSubmitted && this.form() ) {\n
\t\t\t\t$(this.currentForm).submit();\n
\t\t\t\tthis.formSubmitted = false;\n
\t\t\t} else if (!valid && this.pendingRequest === 0 && this.formSubmitted) {\n
\t\t\t\t$(this.currentForm).triggerHandler("invalid-form", [this]);\n
\t\t\t\tthis.formSubmitted = false;\n
\t\t\t}\n
\t\t},\n
\n
\t\tpreviousValue: function( element ) {\n
\t\t\treturn $.data(element, "previousValue") || $.data(element, "previousValue", {\n
\t\t\t\told: null,\n
\t\t\t\tvalid: true,\n
\t\t\t\tmessage: this.defaultMessage( element, "remote" )\n
\t\t\t});\n
\t\t}\n
\n
\t},\n
\n
\tclassRuleSettings: {\n
\t\trequired: {required: true},\n
\t\temail: {email: true},\n
\t\turl: {url: true},\n
\t\tdate: {date: true},\n
\t\tdateISO: {dateISO: true},\n
\t\tnumber: {number: true},\n
\t\tdigits: {digits: true},\n
\t\tcreditcard: {creditcard: true}\n
\t},\n
\n
\taddClassRules: function( className, rules ) {\n
\t\tif ( className.constructor === String ) {\n
\t\t\tthis.classRuleSettings[className] = rules;\n
\t\t} else {\n
\t\t\t$.extend(this.classRuleSettings, className);\n
\t\t}\n
\t},\n
\n
\tclassRules: function( element ) {\n
\t\tvar rules = {};\n
\t\tvar classes = $(element).attr("class");\n
\t\tif ( classes ) {\n
\t\t\t$.each(classes.split(" "), function() {\n
\t\t\t\tif ( this in $.validator.classRuleSettings ) {\n
\t\t\t\t\t$.extend(rules, $.validator.classRuleSettings[this]);\n
\t\t\t\t}\n
\t\t\t});\n
\t\t}\n
\t\treturn rules;\n
\t},\n
\n
\tattributeRules: function( element ) {\n
\t\tvar rules = {};\n
\t\tvar $element = $(element);\n
\t\tvar type = $element[0].getAttribute("type");\n
\n
\t\tfor (var method in $.validator.methods) {\n
\t\t\tvar value;\n
\n
\t\t\t// support for <input required> in both html5 and older browsers\n
\t\t\tif ( method === "required" ) {\n
\t\t\t\tvalue = $element.get(0).getAttribute(method);\n
\t\t\t\t// Some browsers return an empty string for the required attribute\n
\t\t\t\t// and non-HTML5 browsers might have required="" markup\n
\t\t\t\tif ( value === "" ) {\n
\t\t\t\t\tvalue = true;\n
\t\t\t\t}\n
\t\t\t\t// force non-HTML5 browsers to return bool\n
\t\t\t\tvalue = !!value;\n
\t\t\t} else {\n
\t\t\t\tvalue = $element.attr(method);\n
\t\t\t}\n
\n
\t\t\t// convert the value to a number for number inputs, and for text for backwards compability\n
\t\t\t// allows type="date" and others to be compared as strings\n
\t\t\tif ( /min|max/.test( method ) && ( type === null || /number|range|text/.test( type ) ) ) {\n
\t\t\t\tvalue = Number(value);\n
\t\t\t}\n
\n
\t\t\tif ( value ) {\n
\t\t\t\trules[method] = value;\n
\t\t\t} else if ( type === method && type !== \'range\' ) {\n
\t\t\t\t// exception: the jquery validate \'range\' method\n
\t\t\t\t// does not test for the html5 \'range\' type\n
\t\t\t\trules[method] = true;\n
\t\t\t}\n
\t\t}\n
\n
\t\t// maxlength may be returned as -1, 2147483647 (IE) and 524288 (safari) for text inputs\n
\t\tif ( rules.maxlength && /-1|2147483647|524288/.test(rules.maxlength) ) {\n
\t\t\tdelete rules.maxlength;\n
\t\t}\n
\n
\t\treturn rules;\n
\t},\n
\n
\tdataRules: function( element ) {\n
\t\tvar method, value,\n
\t\t\trules = {}, $element = $(element);\n
\t\tfor (method in $.validator.methods) {\n
\t\t\tvalue = $element.data("rule-" + method.toLowerCase());\n
\t\t\tif ( value !== undefined ) {\n
\t\t\t\trules[method] = value;\n
\t\t\t}\n
\t\t}\n
\t\treturn rules;\n
\t},\n
\n
\tstaticRules: function( element ) {\n
\t\tvar rules = {};\n
\t\tvar validator = $.data(element.form, "validator");\n
\t\tif ( validator.settings.rules ) {\n
\t\t\trules = $.validator.normalizeRule(validator.settings.rules[element.name]) || {};\n
\t\t}\n
\t\treturn rules;\n
\t},\n
\n
\tnormalizeRules: function( rules, element ) {\n
\t\t// handle dependency check\n
\t\t$.each(rules, function( prop, val ) {\n
\t\t\t// ignore rule when param is explicitly false, eg. required:false\n
\t\t\tif ( val === false ) {\n
\t\t\t\tdelete rules[prop];\n
\t\t\t\treturn;\n
\t\t\t}\n
\t\t\tif ( val.param || val.depends ) {\n
\t\t\t\tvar keepRule = true;\n
\t\t\t\tswitch (typeof val.depends) {\n
\t\t\t\tcase "string":\n
\t\t\t\t\tkeepRule = !!$(val.depends, element.form).length;\n
\t\t\t\t\tbreak;\n
\t\t\t\tcase "function":\n
\t\t\t\t\tkeepRule = val.depends.call(element, element);\n
\t\t\t\t\tbreak;\n
\t\t\t\t}\n
\t\t\t\tif ( keepRule ) {\n
\t\t\t\t\trules[prop] = val.param !== undefined ? val.param : true;\n
\t\t\t\t} else {\n
\t\t\t\t\tdelete rules[prop];\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\n
\t\t// evaluate parameters\n
\t\t$.each(rules, function( rule, parameter ) {\n
\t\t\trules[rule] = $.isFunction(parameter) ? parameter(element) : parameter;\n
\t\t});\n
\n
\t\t// clean number parameters\n
\t\t$.each([\'minlength\', \'maxlength\'], function() {\n
\t\t\tif ( rules[this] ) {\n
\t\t\t\trules[this] = Number(rules[this]);\n
\t\t\t}\n
\t\t});\n
\t\t$.each([\'rangelength\', \'range\'], function() {\n
\t\t\tvar parts;\n
\t\t\tif ( rules[this] ) {\n
\t\t\t\tif ( $.isArray(rules[this]) ) {\n
\t\t\t\t\trules[this] = [Number(rules[this][0]), Number(rules[this][1])];\n
\t\t\t\t} else if ( typeof rules[this] === "string" ) {\n
\t\t\t\t\tparts = rules[this].split(/[\\s,]+/);\n
\t\t\t\t\trules[this] = [Number(parts[0]), Number(parts[1])];\n
\t\t\t\t}\n
\t\t\t}\n
\t\t});\n
\n
\t\tif ( $.validator.autoCreateRanges ) {\n
\t\t\t// auto-create ranges\n
\t\t\tif ( rules.min && rules.max ) {\n
\t\t\t\trules.range = [rules.min, rules.max];\n
\t\t\t\tdelete rules.min;\n
\t\t\t\tdelete rules.max;\n
\t\t\t}\n
\t\t\tif ( rules.minlength && rules.maxlength ) {\n
\t\t\t\trules.rangelength = [rules.minlength, rules.maxlength];\n
\t\t\t\tdelete rules.minlength;\n
\t\t\t\tdelete rules.maxlength;\n
\t\t\t}\n
\t\t}\n
\n
\t\treturn rules;\n
\t},\n
\n
\t// Converts a simple string to a {string: true} rule, e.g., "required" to {required:true}\n
\tnormalizeRule: function( data ) {\n
\t\tif ( typeof data === "string" ) {\n
\t\t\tvar transformed = {};\n
\t\t\t$.each(data.split(/\\s/), function() {\n
\t\t\t\ttransformed[this] = true;\n
\t\t\t});\n
\t\t\tdata = transformed;\n
\t\t}\n
\t\treturn data;\n
\t},\n
\n
\t// http://docs.jquery.com/Plugins/Validation/Validator/addMethod\n
\taddMethod: function( name, method, message ) {\n
\t\t$.validator.methods[name] = method;\n
\t\t$.validator.messages[name] = message !== undefined ? message : $.validator.messages[name];\n
\t\tif ( method.length < 3 ) {\n
\t\t\t$.validator.addClassRules(name, $.validator.normalizeRule(name));\n
\t\t}\n
\t},\n
\n
\tmethods: {\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/required\n
\t\trequired: function( value, element, param ) {\n
\t\t\t// check if dependency is met\n
\t\t\tif ( !this.depend(param, element) ) {\n
\t\t\t\treturn "dependency-mismatch";\n
\t\t\t}\n
\t\t\tif ( element.nodeName.toLowerCase() === "select" ) {\n
\t\t\t\t// could be an array for select-multiple or a string, both are fine this way\n
\t\t\t\tvar val = $(element).val();\n
\t\t\t\treturn val && val.length > 0;\n
\t\t\t}\n
\t\t\tif ( this.checkable(element) ) {\n
\t\t\t\treturn this.getLength(value, element) > 0;\n
\t\t\t}\n
\t\t\treturn $.trim(value).length > 0;\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/email\n
\t\temail: function( value, element ) {\n
\t\t\t// contributed by Scott Gonzalez: http://projects.scottsplayground.com/email_address_validation/\n
\t\t\treturn this.optional(element) || /^((([a-z]|\\d|[!#\\$%&\'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])+(\\.([a-z]|\\d|[!#\\$%&\'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(\\\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])*([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])))\\.)+(([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])*([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])))$/i.test(value);\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/url\n
\t\turl: function( value, element ) {\n
\t\t\t// contributed by Scott Gonzalez: http://projects.scottsplayground.com/iri/\n
\t\t\treturn this.optional(element) || /^(https?|s?ftp):\\/\\/(((([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(%[\\da-f]{2})|[!\\$&\'\\(\\)\\*\\+,;=]|:)*@)?(((\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5]))|((([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])*([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])))\\.)+(([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])*([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])))\\.?)(:\\d*)?)(\\/((([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(%[\\da-f]{2})|[!\\$&\'\\(\\)\\*\\+,;=]|:|@)+(\\/(([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(%[\\da-f]{2})|[!\\$&\'\\(\\)\\*\\+,;=]|:|@)*)*)?)?(\\?((([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(%[\\da-f]{2})|[!\\$&\'\\(\\)\\*\\+,;=]|:|@)|[\\uE000-\\uF8FF]|\\/|\\?)*)?(#((([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(%[\\da-f]{2})|[!\\$&\'\\(\\)\\*\\+,;=]|:|@)|\\/|\\?)*)?$/i.test(value);\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/date\n
\t\tdate: function( value, element ) {\n
\t\t\treturn this.optional(element) || !/Invalid|NaN/.test(new Date(value).toString());\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/dateISO\n
\t\tdateISO: function( value, element ) {\n
\t\t\treturn this.optional(element) || /^\\d{4}[\\/\\-]\\d{1,2}[\\/\\-]\\d{1,2}$/.test(value);\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/number\n
\t\tnumber: function( value, element ) {\n
\t\t\treturn this.optional(element) || /^-?(?:\\d+|\\d{1,3}(?:,\\d{3})+)?(?:\\.\\d+)?$/.test(value);\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/digits\n
\t\tdigits: function( value, element ) {\n
\t\t\treturn this.optional(element) || /^\\d+$/.test(value);\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/creditcard\n
\t\t// based on http://en.wikipedia.org/wiki/Luhn\n
\t\tcreditcard: function( value, element ) {\n
\t\t\tif ( this.optional(element) ) {\n
\t\t\t\treturn "dependency-mismatch";\n
\t\t\t}\n
\t\t\t// accept only spaces, digits and dashes\n
\t\t\tif ( /[^0-9 \\-]+/.test(value) ) {\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t\tvar nCheck = 0,\n
\t\t\t\tnDigit = 0,\n
\t\t\t\tbEven = false;\n
\n
\t\t\tvalue = value.replace(/\\D/g, "");\n
\n
\t\t\tfor (var n = value.length - 1; n >= 0; n--) {\n
\t\t\t\tvar cDigit = value.charAt(n);\n
\t\t\t\tnDigit = parseInt(cDigit, 10);\n
\t\t\t\tif ( bEven ) {\n
\t\t\t\t\tif ( (nDigit *= 2) > 9 ) {\n
\t\t\t\t\t\tnDigit -= 9;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t\tnCheck += nDigit;\n
\t\t\t\tbEven = !bEven;\n
\t\t\t}\n
\n
\t\t\treturn (nCheck % 10) === 0;\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/minlength\n
\t\tminlength: function( value, element, param ) {\n
\t\t\tvar length = $.isArray( value ) ? value.length : this.getLength($.trim(value), element);\n
\t\t\treturn this.optional(element) || length >= param;\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/maxlength\n
\t\tmaxlength: function( value, element, param ) {\n
\t\t\tvar length = $.isArray( value ) ? value.length : this.getLength($.trim(value), element);\n
\t\t\treturn this.optional(element) || length <= param;\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/rangelength\n
\t\trangelength: function( value, element, param ) {\n
\t\t\tvar length = $.isArray( value ) ? value.length : this.getLength($.trim(value), element);\n
\t\t\treturn this.optional(element) || ( length >= param[0] && length <= param[1] );\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/min\n
\t\tmin: function( value, element, param ) {\n
\t\t\treturn this.optional(element) || value >= param;\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/max\n
\t\tmax: function( value, element, param ) {\n
\t\t\treturn this.optional(element) || value <= param;\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/range\n
\t\trange: function( value, element, param ) {\n
\t\t\treturn this.optional(element) || ( value >= param[0] && value <= param[1] );\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/equalTo\n
\t\tequalTo: function( value, element, param ) {\n
\t\t\t// bind to the blur event of the target in order to revalidate whenever the target field is updated\n
\t\t\t// TODO find a way to bind the event just once, avoiding the unbind-rebind overhead\n
\t\t\tvar target = $(param);\n
\t\t\tif ( this.settings.onfocusout ) {\n
\t\t\t\ttarget.unbind(".validate-equalTo").bind("blur.validate-equalTo", function() {\n
\t\t\t\t\t$(element).valid();\n
\t\t\t\t});\n
\t\t\t}\n
\t\t\treturn value === target.val();\n
\t\t},\n
\n
\t\t// http://docs.jquery.com/Plugins/Validation/Methods/remote\n
\t\tremote: function( value, element, param ) {\n
\t\t\tif ( this.optional(element) ) {\n
\t\t\t\treturn "dependency-mismatch";\n
\t\t\t}\n
\n
\t\t\tvar previous = this.previousValue(element);\n
\t\t\tif (!this.settings.messages[element.name] ) {\n
\t\t\t\tthis.settings.messages[element.name] = {};\n
\t\t\t}\n
\t\t\tprevious.originalMessage = this.settings.messages[element.name].remote;\n
\t\t\tthis.settings.messages[element.name].remote = previous.message;\n
\n
\t\t\tparam = typeof param === "string" && {url:param} || param;\n
\n
\t\t\tif ( previous.old === value ) {\n
\t\t\t\treturn previous.valid;\n
\t\t\t}\n
\n
\t\t\tprevious.old = value;\n
\t\t\tvar validator = this;\n
\t\t\tthis.startRequest(element);\n
\t\t\tvar data = {};\n
\t\t\tdata[element.name] = value;\n
\t\t\t$.ajax($.extend(true, {\n
\t\t\t\turl: param,\n
\t\t\t\tmode: "abort",\n
\t\t\t\tport: "validate" + element.name,\n
\t\t\t\tdataType: "json",\n
\t\t\t\tdata: data,\n
\t\t\t\tsuccess: function( response ) {\n
\t\t\t\t\tvalidator.settings.messages[element.name].remote = previous.originalMessage;\n
\t\t\t\t\tvar valid = response === true || response === "true";\n
\t\t\t\t\tif ( valid ) {\n
\t\t\t\t\t\tvar submitted = validator.formSubmitted;\n
\t\t\t\t\t\tvalidator.prepareElement(element);\n
\t\t\t\t\t\tvalidator.formSubmitted = submitted;\n
\t\t\t\t\t\tvalidator.successList.push(element);\n
\t\t\t\t\t\tdelete validator.invalid[element.name];\n
\t\t\t\t\t\tvalidator.showErrors();\n
\t\t\t\t\t} else {\n
\t\t\t\t\t\tvar errors = {};\n
\t\t\t\t\t\tvar message = response || validator.defaultMessage( element, "remote" );\n
\t\t\t\t\t\terrors[element.name] = previous.message = $.isFunction(message) ? message(value) : message;\n
\t\t\t\t\t\tvalidator.invalid[element.name] = true;\n
\t\t\t\t\t\tvalidator.showErrors(errors);\n
\t\t\t\t\t}\n
\t\t\t\t\tprevious.valid = valid;\n
\t\t\t\t\tvalidator.stopRequest(element, valid);\n
\t\t\t\t}\n
\t\t\t}, param));\n
\t\t\treturn "pending";\n
\t\t}\n
\n
\t}\n
\n
});\n
\n
// deprecated, use $.validator.format instead\n
$.format = $.validator.format;\n
\n
}(jQuery));\n
\n
// ajax mode: abort\n
// usage: $.ajax({ mode: "abort"[, port: "uniqueport"]});\n
// if mode:"abort" is used, the previous request on that port (port can be undefined) is aborted via XMLHttpRequest.abort()\n
(function($) {\n
\tvar pendingRequests = {};\n
\t// Use a prefilter if available (1.5+)\n
\tif ( $.ajaxPrefilter ) {\n
\t\t$.ajaxPrefilter(function( settings, _, xhr ) {\n
\t\t\tvar port = settings.port;\n
\t\t\tif ( settings.mode === "abort" ) {\n
\t\t\t\tif ( pendingRequests[port] ) {\n
\t\t\t\t\tpendingRequests[port].abort();\n
\t\t\t\t}\n
\t\t\t\tpendingRequests[port] = xhr;\n
\t\t\t}\n
\t\t});\n
\t} else {\n
\t\t// Proxy ajax\n
\t\tvar ajax = $.ajax;\n
\t\t$.ajax = function( settings ) {\n
\t\t\tvar mode = ( "mode" in settings ? settings : $.ajaxSettings ).mode,\n
\t\t\t\tport = ( "port" in settings ? settings : $.ajaxSettings ).port;\n
\t\t\tif ( mode === "abort" ) {\n
\t\t\t\tif ( pendingRequests[port] ) {\n
\t\t\t\t\tpendingRequests[port].abort();\n
\t\t\t\t}\n
\t\t\t\tpendingRequests[port] = ajax.apply(this, arguments);\n
\t\t\t\treturn pendingRequests[port];\n
\t\t\t}\n
\t\t\treturn ajax.apply(this, arguments);\n
\t\t};\n
\t}\n
}(jQuery));\n
\n
// provides delegate(type: String, delegate: Selector, handler: Callback) plugin for easier event delegation\n
// handler is only called when $(event.target).is(delegate), in the scope of the jquery-object for event.target\n
(function($) {\n
\t$.extend($.fn, {\n
\t\tvalidateDelegate: function( delegate, type, handler ) {\n
\t\t\treturn this.bind(type, function( event ) {\n
\t\t\t\tvar target = $(event.target);\n
\t\t\t\tif ( target.is(delegate) ) {\n
\t\t\t\t\treturn handler.apply(target, arguments);\n
\t\t\t\t}\n
\t\t\t});\n
\t\t}\n
\t});\n
}(jQuery));\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>38951</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>jquery.validate.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
