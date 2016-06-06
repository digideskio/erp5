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
            <value> <string>ts54096599.77</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>formwizard.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
 * jQuery wizard plug-in 3.0.7 (18-SEPT-2012)\n
 *\n
 *\n
 * Copyright (c) 2012 Jan Sundman (jan.sundman[at]aland.net)\n
 *\n
 * http://www.thecodemine.org\n
 *\n
 * Licensed under the MIT licens:\n
 *   http://www.opensource.org/licenses/mit-license.php\n
 *\n
 */\n
\n
\n
(function($){\n
\t$.widget("ui.formwizard", {\n
\n
\t\t_init: function() {\n
\n
\t\t\tvar wizard = this;\n
\t\t\tvar formOptionsSuccess = this.options.formOptions.success;\n
\t\t\tvar formOptionsComplete = this.options.formOptions.complete;\n
\t\t\tvar formOptionsBeforeSend = this.options.formOptions.beforeSend;\n
\t\t\tvar formOptionsBeforeSubmit = this.options.formOptions.beforeSubmit;\n
\t\t\tvar formOptionsBeforeSerialize = this.options.formOptions.beforeSerialize;\n
\t\t\tthis.options.formOptions = $.extend(this.options.formOptions,{\n
\t\t\t\tsuccess\t: function(responseText, textStatus, xhr){\n
\t\t\t\t\tif(formOptionsSuccess){\n
\t\t\t\t\t\tformOptionsSuccess(responseText, textStatus, xhr);\n
\t\t\t\t\t}\n
\t\t\t\t\tif(wizard.options.formOptions && wizard.options.formOptions.resetForm || !wizard.options.formOptions){\n
\t\t\t\t\t\twizard._reset();\n
\t\t\t\t\t}\n
\t\t\t\t},\n
\t\t\t\tcomplete : function(xhr, textStatus){\n
\t\t\t\t\tif(formOptionsComplete){\n
\t\t\t\t\t\tformOptionsComplete(xhr, textStatus);\n
\t\t\t\t\t}\n
\t\t\t\t\twizard._enableNavigation();\n
\t\t\t\t},\n
\t\t\t\tbeforeSubmit : function(arr, theForm, options) {\n
\t\t\t\t\tif(formOptionsBeforeSubmit){\n
\t\t\t\t\t\tvar shouldSubmit = formOptionsBeforeSubmit(arr, theForm, options);\n
\t\t\t\t\t\tif(!shouldSubmit)\n
\t\t\t\t\t\t\twizard._enableNavigation();\n
\t\t\t\t\t\treturn shouldSubmit;\n
\t\t\t\t\t}\n
\t\t\t\t},\n
\t\t\t\tbeforeSend : function(xhr) {\n
\t\t\t\t\tif(formOptionsBeforeSend){\n
\t\t\t\t\t\tvar shouldSubmit = formOptionsBeforeSend(xhr);\n
\t\t\t\t\t\tif(!shouldSubmit)\n
\t\t\t\t\t\t\twizard._enableNavigation();\n
\t\t\t\t\t\treturn shouldSubmit;\n
\t\t\t\t\t}\n
\t\t\t\t},\n
\t\t\t\tbeforeSerialize: function(form, options) {\n
\t\t\t\t\tif(formOptionsBeforeSerialize){\n
\t\t\t\t\t\tvar shouldSubmit = formOptionsBeforeSerialize(form, options);\n
\t\t\t\t\t\tif(!shouldSubmit)\n
\t\t\t\t\t\t\twizard._enableNavigation();\n
\t\t\t\t\t\treturn shouldSubmit;\n
\t\t\t\t\t}\n
\t\t\t\t}\n
\t\t\t});\n
\t\t\t\n
\t\t\tif (this.options.historyEnabled) {\n
\t\t\t\t$.bbq.removeState("_" + $(this.element).attr(\'id\'));\n
\t\t\t}\n
\n
\t\t\tthis.steps = this.element.find(".step").hide();\n
\n
\t\t\tthis.firstStep = this.steps.eq(0).attr("id");\n
\t\t\tthis.activatedSteps = new Array();\n
\t\t\tthis.isLastStep = false;\n
\t\t\tthis.previousStep = undefined;\n
\t\t\tthis.currentStep = this.steps.eq(0).attr("id");\n
\t\t\tthis.nextButton\t= this.element.find(this.options.next)\n
\t\t\t\t\t.click(function() {\n
\t\t\t\t\t\treturn wizard._next();\n
\t\t\t\t\t});\n
\n
\t\t\tthis.nextButtonInitinalValue = this.nextButton.val();\n
\t\t\tthis.nextButton.val(this.options.textNext);\n
\n
\t\t\t\tthis.backButton\t= this.element.find(this.options.back)\n
\t\t\t\t\t.click(function() {\n
\t\t\t\t\t\twizard._back();return false;\n
\t\t\t\t\t});\n
\n
\t\t\t\tthis.backButtonInitinalValue = this.backButton.val();\n
\t\t\t\tthis.backButton.val(this.options.textBack);\n
\n
\t\t\tif(this.options.validationEnabled && jQuery().validate  == undefined){\n
\t\t\t\tthis.options.validationEnabled = false;\n
\t\t\t\tif( (window[\'console\'] !== undefined) ){\n
\t\t\t\t\tconsole.log("%s", "validationEnabled option set, but the validation plugin is not included");\n
\t\t\t\t}\n
\t\t\t}else if(this.options.validationEnabled){\n
\t\t\t\tthis.element.validate(this.options.validationOptions);\n
\t\t\t}\n
\t\t\tif(this.options.formPluginEnabled && jQuery().ajaxSubmit == undefined){\n
\t\t\t\tthis.options.formPluginEnabled = false;\n
\t\t\t\tif( (window[\'console\'] !== undefined) ){\n
\t\t\t\t\tconsole.log("%s", "formPluginEnabled option set but the form plugin is not included");\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif(this.options.disableInputFields == true){\n
\t\t\t\t$(this.steps).find(":input:not(\'.wizard-ignore\')").attr("disabled","disabled");\n
\t\t\t}\n
\n
\t\t\tif(this.options.historyEnabled){\n
\t\t\t\t$(window).bind(\'hashchange\', undefined, function(event){\n
\t\t\t\t\tvar hashStep = event.getState( "_" + $(wizard.element).attr( \'id\' )) || wizard.firstStep;\n
\t\t\t\t\tif(hashStep !== wizard.currentStep){\n
\t\t\t\t\t\tif(wizard.options.validationEnabled && hashStep === wizard._navigate(wizard.currentStep)){\n
\t\t\t\t\t\t\tif(!wizard.element.valid()){\n
\t\t\t\t\t\t\t\twizard._updateHistory(wizard.currentStep);\n
\t\t\t\t\t\t\t\twizard.element.validate().focusInvalid();\n
\n
\t\t\t\t\t\t\t\treturn false;\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t}\n
\t\t\t\t\t\tif(hashStep !== wizard.currentStep)\n
\t\t\t\t\t\t\twizard._show(hashStep);\n
\t\t\t\t\t}\n
\t\t\t\t});\n
\t\t\t}\n
\n
\t\t\tthis.element.addClass("ui-formwizard");\n
\t\t\tthis.element.find(":input").addClass("ui-wizard-content");\n
\t\t\tthis.steps.addClass("ui-formwizard-content");\n
\t\t\tthis.backButton.addClass("ui-formwizard-button ui-wizard-content");\n
\t\t\tthis.nextButton.addClass("ui-formwizard-button ui-wizard-content");\n
\n
\t\t\tif(!this.options.disableUIStyles){\n
\t\t\t\tthis.element.addClass("ui-helper-reset ui-widget ui-widget-content ui-helper-reset ui-corner-all");\n
\t\t\t\tthis.element.find(":input").addClass("ui-helper-reset ui-state-default");\n
\t\t\t\tthis.steps.addClass("ui-helper-reset ui-corner-all");\n
\t\t\t\tthis.backButton.addClass("ui-helper-reset ui-state-default");\n
\t\t\t\tthis.nextButton.addClass("ui-helper-reset ui-state-default");\n
\t\t\t}\n
\t\t\tthis._show(undefined);\n
\t\t\treturn $(this);\n
\t\t},\n
\n
\t\t_next : function(){\n
\t\t\tif(this.options.validationEnabled){\n
\t\t\t\tif(!this.element.valid()){\n
\t\t\t\t\tthis.element.validate().focusInvalid();\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif(this.options.remoteAjax != undefined){\n
\t\t\t\tvar options = this.options.remoteAjax[this.currentStep];\n
\t\t\t\tvar wizard = this;\n
\t\t\t\tif(options !== undefined){\n
\t\t\t\t\tvar success = options.success;\n
\t\t\t\t\tvar beforeSend = options.beforeSend;\n
\t\t\t\t\tvar complete = options.complete;\n
\n
\t\t\t\t\toptions = $.extend({},options,{\n
\t\t\t\t\t\tsuccess: function(data, statusText){\n
\t\t\t\t\t\t\tif((success !== undefined && success(data, statusText)) || (success == undefined)){\n
\t\t\t\t\t\t\t\twizard._continueToNextStep();\n
\t\t\t\t\t\t\t}\n
\t\t\t\t\t\t},\n
\t\t\t\t\t\tbeforeSend : function(xhr){\n
\t\t\t\t\t\t\twizard._disableNavigation();\n
\t\t\t\t\t\t\tif(beforeSend !== undefined)\n
\t\t\t\t\t\t\t\tbeforeSend(xhr);\n
\t\t\t\t\t\t\t$(wizard.element).trigger(\'before_remote_ajax\', {"currentStep" : wizard.currentStep});\n
\t\t\t\t\t\t},\n
\t\t\t\t\t\tcomplete : function(xhr, statusText){\n
\t\t\t\t\t\t\tif(complete !== undefined)\n
\t\t\t\t\t\t\t\tcomplete(xhr, statusText);\n
\t\t\t\t\t\t\t$(wizard.element).trigger(\'after_remote_ajax\', {"currentStep" : wizard.currentStep});\n
\t\t\t\t\t\t\twizard._enableNavigation();\n
\t\t\t\t\t\t}\n
\t\t\t\t\t})\n
\t\t\t\t\tthis.element.ajaxSubmit(options);\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\treturn this._continueToNextStep();\n
\t\t},\n
\n
\t\t_back : function(){\n
\t\t\tif(this.activatedSteps.length > 0){\n
\t\t\t\tif(this.options.historyEnabled){\n
\t\t\t\t\tthis._updateHistory(this.activatedSteps[this.activatedSteps.length - 2]);\n
\t\t\t\t}else{\n
\t\t\t\t\tthis._show(this.activatedSteps[this.activatedSteps.length - 2], true);\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn false;\n
\t\t},\n
\n
\t\t_continueToNextStep : function(){\n
\t\t\tif(this.isLastStep){\n
\t\t\t\tfor(var i = 0; i < this.activatedSteps.length; i++){\n
\t\t\t\t\tthis.steps.filter("#" + this.activatedSteps[i]).find(":input").not(".wizard-ignore").removeAttr("disabled");\n
\t\t\t\t}\n
\t\t\t\tif(!this.options.formPluginEnabled){\n
\t\t\t\t\treturn true;\n
\t\t\t\t}else{\n
\t\t\t\t\tthis._disableNavigation();\n
\t\t\t\t\tthis.element.ajaxSubmit(this.options.formOptions);\n
\t\t\t\t\treturn false;\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tvar step = this._navigate(this.currentStep);\n
\t\t\tif(step == this.currentStep){\n
\t\t\t\treturn false;\n
\t\t\t}\n
\t\t\tif(this.options.historyEnabled){\n
\t\t\t\tthis._updateHistory(step);\n
\t\t\t}else{\n
\t\t\t\tthis._show(step, true);\n
\t\t\t}\n
\t\t\treturn false;\n
\t\t},\n
\n
\t\t_updateHistory : function(step){\n
\t\t\tvar state = {};\n
\t\t\tstate["_" + $(this.element).attr(\'id\')] = step;\n
\t\t\t$.bbq.pushState(state);\n
\t\t},\n
\n
\t\t_disableNavigation : function(){\n
\t\t\tthis.nextButton.attr("disabled","disabled");\n
\t\t\tthis.backButton.attr("disabled","disabled");\n
\t\t\tif(!this.options.disableUIStyles){\n
\t\t\t\tthis.nextButton.removeClass("ui-state-active").addClass("ui-state-disabled");\n
\t\t\t\tthis.backButton.removeClass("ui-state-active").addClass("ui-state-disabled");\n
\t\t\t}\n
\t\t},\n
\n
\t\t_enableNavigation : function(){\n
\t\t\tif(this.isLastStep){\n
\t\t\t\tthis.nextButton.val(this.options.textSubmit);\n
\t\t\t}else{\n
\t\t\t\tthis.nextButton.val(this.options.textNext);\n
\t\t\t}\n
\n
\t\t\tif($.trim(this.currentStep) !== this.steps.eq(0).attr("id")){\n
\t\t\t\tthis.backButton.removeAttr("disabled");\n
\t\t\t\tif(!this.options.disableUIStyles){\n
\t\t\t\t\tthis.backButton.removeClass("ui-state-disabled").addClass("ui-state-active");\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tthis.nextButton.removeAttr("disabled");\n
\t\t\tif(!this.options.disableUIStyles){\n
\t\t\t\tthis.nextButton.removeClass("ui-state-disabled").addClass("ui-state-active");\n
\t\t\t}\n
\t\t},\n
\n
\t\t_animate : function(oldStep, newStep, stepShownCallback){\n
\t\t\tthis._disableNavigation();\n
\t\t\tvar old = this.steps.filter("#" + oldStep);\n
\t\t\tvar current = this.steps.filter("#" + newStep);\n
\t\t\told.find(":input").not(".wizard-ignore").attr("disabled","disabled");\n
\t\t\tcurrent.find(":input").not(".wizard-ignore").removeAttr("disabled");\n
\t\t\tvar wizard = this;\n
\t\t\told.animate(wizard.options.outAnimation, wizard.options.outDuration, wizard.options.easing, function(){\n
\t\t\t\tcurrent.animate(wizard.options.inAnimation, wizard.options.inDuration, wizard.options.easing, function(){\n
\t\t\t\t\tif(wizard.options.focusFirstInput)\n
\t\t\t\t\t\tcurrent.find(":input:first").focus();\n
\t\t\t\t\twizard._enableNavigation();\n
\n
\t\t\t\t\tstepShownCallback.apply(wizard);\n
\t\t\t\t});\n
\t\t\t\treturn;\n
\t\t\t});\n
\t\t},\n
\n
\t\t_checkIflastStep : function(step){\n
\t\t\tthis.isLastStep = false;\n
\t\t\tif($("#" + step).hasClass(this.options.submitStepClass) || this.steps.filter(":last").attr("id") == step){\n
\t\t\t\tthis.isLastStep = true;\n
\t\t\t}\n
\t\t},\n
\n
\t\t_getLink : function(step){\n
\t\t\tvar link = undefined;\n
\t\t\tvar links = this.steps.filter("#" + step).find(this.options.linkClass);\n
\n
\t\t\tif(links != undefined){\n
\t\t\t\tif(links.filter(":radio,:checkbox").size() > 0){\n
\t\t\t\t\tlink = links.filter(this.options.linkClass + ":checked").val();\n
\t\t\t\t}else{\n
\t\t\t\t\tlink = $(links).val();\n
\t\t\t\t}\n
\t\t\t}\n
\t\t\treturn link;\n
\t\t},\n
\n
\t\t_navigate : function(step){\n
\t\t\tvar link = this._getLink(step);\n
\t\t\tif(link != undefined){\n
\t\t\t\tif((link != "" && link != null && link != undefined) && this.steps.filter("#" + link).attr("id") != undefined){\n
\t\t\t\t\treturn link;\n
\t\t\t\t}\n
\t\t\t\treturn this.currentStep;\n
\t\t\t}else if(link == undefined && !this.isLastStep){\n
\t\t\t\tvar step1 =  this.steps.filter("#" + step).next().attr("id");\n
\t\t\t\treturn step1;\n
\t\t\t}\n
\t\t},\n
\n
\t\t_show : function(step){\n
\t\t\tvar backwards = false;\n
\t\t\tvar triggerStepShown = step !== undefined;\n
\t\t\tif(step == undefined || step == ""){\n
\t\t\t\t\tthis.activatedSteps.pop();\n
\t\t\t\t\tstep = this.firstStep;\n
\t\t\t\t\tthis.activatedSteps.push(step);\n
\t\t\t}else{\n
\t\t\t\tif($.inArray(step, this.activatedSteps) > -1){\n
\t\t\t\t\tbackwards = true;\n
\t\t\t\t\tthis.activatedSteps.pop();\n
\t\t\t\t}else {\n
\t\t\t\t\tthis.activatedSteps.push(step);\n
\t\t\t\t}\n
\t\t\t}\n
\n
\t\t\tif(this.currentStep !== step || step === this.firstStep){\n
\t\t\t\tthis.previousStep = this.currentStep;\n
\t\t\t\tthis._checkIflastStep(step);\n
\t\t\t\tthis.currentStep = step;\n
\t\t\t\tvar stepShownCallback = function(){if(triggerStepShown){$(this.element).trigger(\'step_shown\', $.extend({"isBackNavigation" : backwards},this._state()));}}\n
\t\t\t\tif(triggerStepShown){\n
\t\t\t\t\t$(this.element).trigger(\'before_step_shown\', $.extend({"isBackNavigation" : backwards},this._state()));\n
\t\t\t\t}\n
\t\t\t\tthis._animate(this.previousStep, step, stepShownCallback);\n
\t\t\t};\n
\n
\n
\t\t},\n
\n
\t   _reset : function(){\n
\t\t\tthis.element.resetForm()\n
\t\t\t$("label,:input,textarea",this).removeClass("error");\n
\t\t\tfor(var i = 0; i < this.activatedSteps.length; i++){\n
\t\t\t\tthis.steps.filter("#" + this.activatedSteps[i]).hide().find(":input").attr("disabled","disabled");\n
\t\t\t}\n
\t\t\tthis.activatedSteps = new Array();\n
\t\t\tthis.previousStep = undefined;\n
\t\t\tthis.isLastStep = false;\n
\t\t\tif(this.options.historyEnabled){\n
\t\t\t\tthis._updateHistory(this.firstStep);\n
\t\t\t}else{\n
\t\t\t\tthis._show(this.firstStep);\n
\t\t\t}\n
\n
\t\t},\n
\n
\t\t_state : function(state){\n
\t\t\tvar currentState = { "settings" : this.options,\n
\t\t\t\t"activatedSteps" : this.activatedSteps,\n
\t\t\t\t"isLastStep" : this.isLastStep,\n
\t\t\t\t"isFirstStep" : this.currentStep === this.firstStep,\n
\t\t\t\t"previousStep" : this.previousStep,\n
\t\t\t\t"currentStep" : this.currentStep,\n
\t\t\t\t"backButton" : this.backButton,\n
\t\t\t\t"nextButton" : this.nextButton,\n
\t\t\t\t"steps" : this.steps,\n
\t\t\t\t"firstStep" : this.firstStep\n
\t\t\t}\n
\n
\t\t\tif(state !== undefined)\n
\t\t\t\treturn currentState[state];\n
\n
\t\t\treturn currentState;\n
\t\t},\n
\n
\t  /*Methods*/\n
\n
\t\tshow : function(step){\n
\t\t\tif(this.options.historyEnabled){\n
\t\t\t\tthis._updateHistory(step);\n
\t\t\t}else{\n
\t\t\t\tthis._show(step);\n
\t\t\t}\n
\t\t},\n
\n
\t\tstate : function(state){\n
\t\t\treturn this._state(state);\n
\t\t},\n
\n
\t\treset : function(){\n
\t\t\tthis._reset();\n
\t\t},\n
\n
\t\tnext : function(){\n
\t\t\tthis._next();\n
\t\t},\n
\n
\t\tback : function(){\n
\t\t\tthis._back();\n
\t\t},\n
\n
\t\tdestroy: function() {\n
\t\t\tthis.element.find("*").removeAttr("disabled").show();\n
\t\t\tthis.nextButton.unbind("click").val(this.nextButtonInitinalValue).removeClass("ui-state-disabled").addClass("ui-state-active");\n
\t\t\tthis.backButton.unbind("click").val(this.backButtonInitinalValue).removeClass("ui-state-disabled").addClass("ui-state-active");\n
\t\t\tthis.backButtonInitinalValue = undefined;\n
\t\t\tthis.nextButtonInitinalValue = undefined;\n
\t\t\tthis.activatedSteps = undefined;\n
\t\t\tthis.previousStep = undefined;\n
\t\t\tthis.currentStep = undefined;\n
\t\t\tthis.isLastStep = undefined;\n
\t\t\tthis.options = undefined;\n
\t\t\tthis.nextButton = undefined;\n
\t\t\tthis.backButton = undefined;\n
\t\t\tthis.formwizard = undefined;\n
\t\t\tthis.element = undefined;\n
\t\t\tthis.steps = undefined;\n
\t\t\tthis.firstStep = undefined;\n
\t\t},\n
\n
\t\tupdate_steps : function(){\n
\t\t\tthis.steps = this.element.find(".step").addClass("ui-formwizard-content");\n
\t\t\tthis.firstStep = this.steps.eq(0).attr("id");\n
\t\t\tthis.steps.not("#" + this.currentStep).hide().find(":input").addClass("ui-wizard-content").attr("disabled","disabled");\n
\t\t\tthis._checkIflastStep(this.currentStep);\n
\t\t\tthis._enableNavigation();\n
\t\t\tif(!this.options.disableUIStyles){\n
\t\t\t\tthis.steps.addClass("ui-helper-reset ui-corner-all");\n
\t\t\t\tthis.steps.find(":input").addClass("ui-helper-reset ui-state-default");\n
\t\t\t}\n
\t\t},\n
\n
\t\toptions: {\n
\t   \t\thistoryEnabled\t: false,\n
\t\t\tvalidationEnabled : false,\n
\t\t\tvalidationOptions : undefined,\n
\t\t\tformPluginEnabled : false,\n
\t\t\tlinkClass\t: ".link",\n
\t\t\tsubmitStepClass : "submit_step",\n
\t\t\tback : ":reset",\n
\t\t\tnext : ":submit",\n
\t\t\ttextSubmit : \'Submit\',\n
\t\t\ttextNext : \'Next\',\n
\t\t\ttextBack : \'Back\',\n
\t\t\tremoteAjax : undefined,\n
\t\t\tinAnimation : {opacity: \'show\'},\n
\t\t\toutAnimation: {opacity: \'hide\'},\n
\t\t\tinDuration : 400,\n
\t\t\toutDuration: 400,\n
\t\t\teasing: \'swing\',\n
\t\t\tfocusFirstInput : false,\n
\t\t\tdisableInputFields : true,\n
\t\t\tformOptions : { reset: true, success: function(data) { if( (window[\'console\'] !== undefined) ){console.log("%s", "form submit successful");}},\n
\t\t\tdisableUIStyles : false\n
\t\t}\n
   }\n
 });\n
})(jQuery);\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>14327</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>formwizard.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
