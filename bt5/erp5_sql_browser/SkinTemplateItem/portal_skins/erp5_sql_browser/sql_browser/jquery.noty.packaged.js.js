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
            <value> <string>ts32635766.77</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>jquery.noty.packaged.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

!function(root, factory) {\n
\t if (typeof define === \'function\' && define.amd) {\n
\t\t define([\'jquery\'], factory);\n
\t } else if (typeof exports === \'object\') {\n
\t\t module.exports = factory(require(\'jquery\'));\n
\t } else {\n
\t\t factory(root.jQuery);\n
\t }\n
}(this, function($) {\n
\n
/*!\n
 @package noty - jQuery Notification Plugin\n
 @version version: 2.3.5\n
 @contributors https://github.com/needim/noty/graphs/contributors\n
\n
 @documentation Examples and Documentation - http://needim.github.com/noty/\n
\n
 @license Licensed under the MIT licenses: http://www.opensource.org/licenses/mit-license.php\n
 */\n
\n
    if(typeof Object.create !== \'function\') {\n
        Object.create = function(o) {\n
            function F() {\n
            }\n
\n
            F.prototype = o;\n
            return new F();\n
        };\n
    }\n
\n
    var NotyObject = {\n
\n
        init: function(options) {\n
\n
            // Mix in the passed in options with the default options\n
            this.options = $.extend({}, $.noty.defaults, options);\n
\n
            this.options.layout = (this.options.custom) ? $.noty.layouts[\'inline\'] : $.noty.layouts[this.options.layout];\n
\n
            if($.noty.themes[this.options.theme])\n
                this.options.theme = $.noty.themes[this.options.theme];\n
            else\n
                options.themeClassName = this.options.theme;\n
\n
            delete options.layout;\n
            delete options.theme;\n
\n
            this.options = $.extend({}, this.options, this.options.layout.options);\n
            this.options.id = \'noty_\' + (new Date().getTime() * Math.floor(Math.random() * 1000000));\n
\n
            this.options = $.extend({}, this.options, options);\n
\n
            // Build the noty dom initial structure\n
            this._build();\n
\n
            // return this so we can chain/use the bridge with less code.\n
            return this;\n
        }, // end init\n
\n
        _build: function() {\n
\n
            // Generating noty bar\n
            var $bar = $(\'<div class="noty_bar noty_type_\' + this.options.type + \'"></div>\').attr(\'id\', this.options.id);\n
            $bar.append(this.options.template).find(\'.noty_text\').html(this.options.text);\n
\n
            this.$bar = (this.options.layout.parent.object !== null) ? $(this.options.layout.parent.object).css(this.options.layout.parent.css).append($bar) : $bar;\n
\n
            if(this.options.themeClassName)\n
                this.$bar.addClass(this.options.themeClassName).addClass(\'noty_container_type_\' + this.options.type);\n
\n
            // Set buttons if available\n
            if(this.options.buttons) {\n
\n
                // If we have button disable closeWith & timeout options\n
                this.options.closeWith = [];\n
                this.options.timeout = false;\n
\n
                var $buttons = $(\'<div/>\').addClass(\'noty_buttons\');\n
\n
                (this.options.layout.parent.object !== null) ? this.$bar.find(\'.noty_bar\').append($buttons) : this.$bar.append($buttons);\n
\n
                var self = this;\n
\n
                $.each(this.options.buttons, function(i, button) {\n
                    var $button = $(\'<button/>\').addClass((button.addClass) ? button.addClass : \'gray\').html(button.text).attr(\'id\', button.id ? button.id : \'button-\' + i)\n
                        .appendTo(self.$bar.find(\'.noty_buttons\'))\n
                        .on(\'click\', function(event) {\n
                            if($.isFunction(button.onClick)) {\n
                                button.onClick.call($button, self, event);\n
                            }\n
                        });\n
                });\n
            }\n
\n
            // For easy access\n
            this.$message = this.$bar.find(\'.noty_message\');\n
            this.$closeButton = this.$bar.find(\'.noty_close\');\n
            this.$buttons = this.$bar.find(\'.noty_buttons\');\n
\n
            $.noty.store[this.options.id] = this; // store noty for api\n
\n
        }, // end _build\n
\n
        show: function() {\n
\n
            var self = this;\n
\n
            (self.options.custom) ? self.options.custom.find(self.options.layout.container.selector).append(self.$bar) : $(self.options.layout.container.selector).append(self.$bar);\n
\n
            if(self.options.theme && self.options.theme.style)\n
                self.options.theme.style.apply(self);\n
\n
            ($.type(self.options.layout.css) === \'function\') ? this.options.layout.css.apply(self.$bar) : self.$bar.css(this.options.layout.css || {});\n
\n
            self.$bar.addClass(self.options.layout.addClass);\n
\n
            self.options.layout.container.style.apply($(self.options.layout.container.selector));\n
\n
            self.showing = true;\n
\n
            if(self.options.theme && self.options.theme.style)\n
                self.options.theme.callback.onShow.apply(this);\n
\n
            if($.inArray(\'click\', self.options.closeWith) > -1)\n
                self.$bar.css(\'cursor\', \'pointer\').one(\'click\', function(evt) {\n
                    self.stopPropagation(evt);\n
                    if(self.options.callback.onCloseClick) {\n
                        self.options.callback.onCloseClick.apply(self);\n
                    }\n
                    self.close();\n
                });\n
\n
            if($.inArray(\'hover\', self.options.closeWith) > -1)\n
                self.$bar.one(\'mouseenter\', function() {\n
                    self.close();\n
                });\n
\n
            if($.inArray(\'button\', self.options.closeWith) > -1)\n
                self.$closeButton.one(\'click\', function(evt) {\n
                    self.stopPropagation(evt);\n
                    self.close();\n
                });\n
\n
            if($.inArray(\'button\', self.options.closeWith) == -1)\n
                self.$closeButton.remove();\n
\n
            if(self.options.callback.onShow)\n
                self.options.callback.onShow.apply(self);\n
\n
            if (typeof self.options.animation.open == \'string\') {\n
                self.$bar.css(\'height\', self.$bar.innerHeight());\n
                self.$bar.show().addClass(self.options.animation.open).one(\'webkitAnimationEnd mozAnimationEnd MSAnimationEnd oanimationend animationend\', function() {\n
                    if(self.options.callback.afterShow) self.options.callback.afterShow.apply(self);\n
                    self.showing = false;\n
                    self.shown = true;\n
                });\n
\n
            } else {\n
                self.$bar.animate(\n
                    self.options.animation.open,\n
                    self.options.animation.speed,\n
                    self.options.animation.easing,\n
                    function() {\n
                        if(self.options.callback.afterShow) self.options.callback.afterShow.apply(self);\n
                        self.showing = false;\n
                        self.shown = true;\n
                    });\n
            }\n
\n
            // If noty is have a timeout option\n
            if(self.options.timeout)\n
                self.$bar.delay(self.options.timeout).promise().done(function() {\n
                    self.close();\n
                });\n
\n
            return this;\n
\n
        }, // end show\n
\n
        close: function() {\n
\n
            if(this.closed) return;\n
            if(this.$bar && this.$bar.hasClass(\'i-am-closing-now\')) return;\n
\n
            var self = this;\n
\n
            if(this.showing) {\n
                self.$bar.queue(\n
                    function() {\n
                        self.close.apply(self);\n
                    }\n
                );\n
                return;\n
            }\n
\n
            if(!this.shown && !this.showing) { // If we are still waiting in the queue just delete from queue\n
                var queue = [];\n
                $.each($.noty.queue, function(i, n) {\n
                    if(n.options.id != self.options.id) {\n
                        queue.push(n);\n
                    }\n
                });\n
                $.noty.queue = queue;\n
                return;\n
            }\n
\n
            self.$bar.addClass(\'i-am-closing-now\');\n
\n
            if(self.options.callback.onClose) {\n
                self.options.callback.onClose.apply(self);\n
            }\n
\n
            if (typeof self.options.animation.close == \'string\') {\n
                self.$bar.addClass(self.options.animation.close).one(\'webkitAnimationEnd mozAnimationEnd MSAnimationEnd oanimationend animationend\', function() {\n
                    if(self.options.callback.afterClose) self.options.callback.afterClose.apply(self);\n
                    self.closeCleanUp();\n
                });\n
            } else {\n
                self.$bar.clearQueue().stop().animate(\n
                    self.options.animation.close,\n
                    self.options.animation.speed,\n
                    self.options.animation.easing,\n
                    function() {\n
                        if(self.options.callback.afterClose) self.options.callback.afterClose.apply(self);\n
                    })\n
                    .promise().done(function() {\n
                        self.closeCleanUp();\n
                    });\n
            }\n
\n
        }, // end close\n
\n
        closeCleanUp: function() {\n
\n
            var self = this;\n
\n
            // Modal Cleaning\n
            if(self.options.modal) {\n
                $.notyRenderer.setModalCount(-1);\n
                if($.notyRenderer.getModalCount() == 0) $(\'.noty_modal\').fadeOut(\'fast\', function() {\n
                    $(this).remove();\n
                });\n
            }\n
\n
            // Layout Cleaning\n
            $.notyRenderer.setLayoutCountFor(self, -1);\n
            if($.notyRenderer.getLayoutCountFor(self) == 0) $(self.options.layout.container.selector).remove();\n
\n
            // Make sure self.$bar has not been removed before attempting to remove it\n
            if(typeof self.$bar !== \'undefined\' && self.$bar !== null) {\n
\n
                if (typeof self.options.animation.close == \'string\') {\n
                    self.$bar.css(\'transition\', \'all 100ms ease\').css(\'border\', 0).css(\'margin\', 0).height(0);\n
                    self.$bar.one(\'transitionend webkitTransitionEnd oTransitionEnd MSTransitionEnd\', function() {\n
                        self.$bar.remove();\n
                        self.$bar = null;\n
                        self.closed = true;\n
\n
                        if(self.options.theme.callback && self.options.theme.callback.onClose) {\n
                            self.options.theme.callback.onClose.apply(self);\n
                        }\n
                    });\n
                } else {\n
                    self.$bar.remove();\n
                    self.$bar = null;\n
                    self.closed = true;\n
                }\n
            }\n
\n
            delete $.noty.store[self.options.id]; // deleting noty from store\n
\n
            if(self.options.theme.callback && self.options.theme.callback.onClose) {\n
                self.options.theme.callback.onClose.apply(self);\n
            }\n
\n
            if(!self.options.dismissQueue) {\n
                // Queue render\n
                $.noty.ontap = true;\n
\n
                $.notyRenderer.render();\n
            }\n
\n
            if(self.options.maxVisible > 0 && self.options.dismissQueue) {\n
                $.notyRenderer.render();\n
            }\n
\n
        }, // end close clean up\n
\n
        setText: function(text) {\n
            if(!this.closed) {\n
                this.options.text = text;\n
                this.$bar.find(\'.noty_text\').html(text);\n
            }\n
            return this;\n
        },\n
\n
        setType: function(type) {\n
            if(!this.closed) {\n
                this.options.type = type;\n
                this.options.theme.style.apply(this);\n
                this.options.theme.callback.onShow.apply(this);\n
            }\n
            return this;\n
        },\n
\n
        setTimeout: function(time) {\n
            if(!this.closed) {\n
                var self = this;\n
                this.options.timeout = time;\n
                self.$bar.delay(self.options.timeout).promise().done(function() {\n
                    self.close();\n
                });\n
            }\n
            return this;\n
        },\n
\n
        stopPropagation: function(evt) {\n
            evt = evt || window.event;\n
            if(typeof evt.stopPropagation !== "undefined") {\n
                evt.stopPropagation();\n
            }\n
            else {\n
                evt.cancelBubble = true;\n
            }\n
        },\n
\n
        closed : false,\n
        showing: false,\n
        shown  : false\n
\n
    }; // end NotyObject\n
\n
    $.notyRenderer = {};\n
\n
    $.notyRenderer.init = function(options) {\n
\n
        // Renderer creates a new noty\n
        var notification = Object.create(NotyObject).init(options);\n
\n
        if(notification.options.killer)\n
            $.noty.closeAll();\n
\n
        (notification.options.force) ? $.noty.queue.unshift(notification) : $.noty.queue.push(notification);\n
\n
        $.notyRenderer.render();\n
\n
        return ($.noty.returns == \'object\') ? notification : notification.options.id;\n
    };\n
\n
    $.notyRenderer.render = function() {\n
\n
        var instance = $.noty.queue[0];\n
\n
        if($.type(instance) === \'object\') {\n
            if(instance.options.dismissQueue) {\n
                if(instance.options.maxVisible > 0) {\n
                    if($(instance.options.layout.container.selector + \' li\').length < instance.options.maxVisible) {\n
                        $.notyRenderer.show($.noty.queue.shift());\n
                    }\n
                    else {\n
\n
                    }\n
                }\n
                else {\n
                    $.notyRenderer.show($.noty.queue.shift());\n
                }\n
            }\n
            else {\n
                if($.noty.ontap) {\n
                    $.notyRenderer.show($.noty.queue.shift());\n
                    $.noty.ontap = false;\n
                }\n
            }\n
        }\n
        else {\n
            $.noty.ontap = true; // Queue is over\n
        }\n
\n
    };\n
\n
    $.notyRenderer.show = function(notification) {\n
\n
        if(notification.options.modal) {\n
            $.notyRenderer.createModalFor(notification);\n
            $.notyRenderer.setModalCount(+1);\n
        }\n
\n
        // Where is the container?\n
        if(notification.options.custom) {\n
            if(notification.options.custom.find(notification.options.layout.container.selector).length == 0) {\n
                notification.options.custom.append($(notification.options.layout.container.object).addClass(\'i-am-new\'));\n
            }\n
            else {\n
                notification.options.custom.find(notification.options.layout.container.selector).removeClass(\'i-am-new\');\n
            }\n
        }\n
        else {\n
            if($(notification.options.layout.container.selector).length == 0) {\n
                $(\'body\').append($(notification.options.layout.container.object).addClass(\'i-am-new\'));\n
            }\n
            else {\n
                $(notification.options.layout.container.selector).removeClass(\'i-am-new\');\n
            }\n
        }\n
\n
        $.notyRenderer.setLayoutCountFor(notification, +1);\n
\n
        notification.show();\n
    };\n
\n
    $.notyRenderer.createModalFor = function(notification) {\n
        if($(\'.noty_modal\').length == 0) {\n
            var modal = $(\'<div/>\').addClass(\'noty_modal\').addClass(notification.options.theme).data(\'noty_modal_count\', 0);\n
\n
            if(notification.options.theme.modal && notification.options.theme.modal.css)\n
                modal.css(notification.options.theme.modal.css);\n
\n
            modal.prependTo($(\'body\')).fadeIn(\'fast\');\n
\n
            if($.inArray(\'backdrop\', notification.options.closeWith) > -1)\n
                modal.on(\'click\', function(e) {\n
                    $.noty.closeAll();\n
                });\n
        }\n
    };\n
\n
    $.notyRenderer.getLayoutCountFor = function(notification) {\n
        return $(notification.options.layout.container.selector).data(\'noty_layout_count\') || 0;\n
    };\n
\n
    $.notyRenderer.setLayoutCountFor = function(notification, arg) {\n
        return $(notification.options.layout.container.selector).data(\'noty_layout_count\', $.notyRenderer.getLayoutCountFor(notification) + arg);\n
    };\n
\n
    $.notyRenderer.getModalCount = function() {\n
        return $(\'.noty_modal\').data(\'noty_modal_count\') || 0;\n
    };\n
\n
    $.notyRenderer.setModalCount = function(arg) {\n
        return $(\'.noty_modal\').data(\'noty_modal_count\', $.notyRenderer.getModalCount() + arg);\n
    };\n
\n
    // This is for custom container\n
    $.fn.noty = function(options) {\n
        options.custom = $(this);\n
        return $.notyRenderer.init(options);\n
    };\n
\n
    $.noty = {};\n
    $.noty.queue = [];\n
    $.noty.ontap = true;\n
    $.noty.layouts = {};\n
    $.noty.themes = {};\n
    $.noty.returns = \'object\';\n
    $.noty.store = {};\n
\n
    $.noty.get = function(id) {\n
        return $.noty.store.hasOwnProperty(id) ? $.noty.store[id] : false;\n
    };\n
\n
    $.noty.close = function(id) {\n
        return $.noty.get(id) ? $.noty.get(id).close() : false;\n
    };\n
\n
    $.noty.setText = function(id, text) {\n
        return $.noty.get(id) ? $.noty.get(id).setText(text) : false;\n
    };\n
\n
    $.noty.setType = function(id, type) {\n
        return $.noty.get(id) ? $.noty.get(id).setType(type) : false;\n
    };\n
\n
    $.noty.clearQueue = function() {\n
        $.noty.queue = [];\n
    };\n
\n
    $.noty.closeAll = function() {\n
        $.noty.clearQueue();\n
        $.each($.noty.store, function(id, noty) {\n
            noty.close();\n
        });\n
    };\n
\n
    var windowAlert = window.alert;\n
\n
    $.noty.consumeAlert = function(options) {\n
        window.alert = function(text) {\n
            if(options)\n
                options.text = text;\n
            else\n
                options = {text: text};\n
\n
            $.notyRenderer.init(options);\n
        };\n
    };\n
\n
    $.noty.stopConsumeAlert = function() {\n
        window.alert = windowAlert;\n
    };\n
\n
    $.noty.defaults = {\n
        layout      : \'top\',\n
        theme       : \'defaultTheme\',\n
        type        : \'alert\',\n
        text        : \'\',\n
        dismissQueue: true,\n
        template    : \'<div class="noty_message"><span class="noty_text"></span><div class="noty_close"></div></div>\',\n
        animation   : {\n
            open  : {height: \'toggle\'},\n
            close : {height: \'toggle\'},\n
            easing: \'swing\',\n
            speed : 500\n
        },\n
        timeout     : false,\n
        force       : false,\n
        modal       : false,\n
        maxVisible  : 5,\n
        killer      : false,\n
        closeWith   : [\'click\'],\n
        callback    : {\n
            onShow      : function() {\n
            },\n
            afterShow   : function() {\n
            },\n
            onClose     : function() {\n
            },\n
            afterClose  : function() {\n
            },\n
            onCloseClick: function() {\n
            }\n
        },\n
        buttons     : false\n
    };\n
\n
    $(window).on(\'resize\', function() {\n
        $.each($.noty.layouts, function(index, layout) {\n
            layout.container.style.apply($(layout.container.selector));\n
        });\n
    });\n
\n
    // Helpers\n
    window.noty = function noty(options) {\n
        return $.notyRenderer.init(options);\n
    };\n
\n
$.noty.layouts.bottom = {\n
    name     : \'bottom\',\n
    options  : {},\n
    container: {\n
        object  : \'<ul id="noty_bottom_layout_container" />\',\n
        selector: \'ul#noty_bottom_layout_container\',\n
        style   : function() {\n
            $(this).css({\n
                bottom       : 0,\n
                left         : \'5%\',\n
                position     : \'fixed\',\n
                width        : \'90%\',\n
                height       : \'auto\',\n
                margin       : 0,\n
                padding      : 0,\n
                listStyleType: \'none\',\n
                zIndex       : 9999999\n
            });\n
        }\n
    },\n
    parent   : {\n
        object  : \'<li />\',\n
        selector: \'li\',\n
        css     : {}\n
    },\n
    css      : {\n
        display: \'none\'\n
    },\n
    addClass : \'\'\n
};\n
\n
$.noty.layouts.bottomCenter = {\n
    name     : \'bottomCenter\',\n
    options  : { // overrides options\n
\n
    },\n
    container: {\n
        object  : \'<ul id="noty_bottomCenter_layout_container" />\',\n
        selector: \'ul#noty_bottomCenter_layout_container\',\n
        style   : function() {\n
            $(this).css({\n
                bottom       : 20,\n
                left         : 0,\n
                position     : \'fixed\',\n
                width        : \'310px\',\n
                height       : \'auto\',\n
                margin       : 0,\n
                padding      : 0,\n
                listStyleType: \'none\',\n
                zIndex       : 10000000\n
            });\n
\n
            $(this).css({\n
                left: ($(window).width() - $(this).outerWidth(false)) / 2 + \'px\'\n
            });\n
        }\n
    },\n
    parent   : {\n
        object  : \'<li />\',\n
        selector: \'li\',\n
        css     : {}\n
    },\n
    css      : {\n
        display: \'none\',\n
        width  : \'310px\'\n
    },\n
    addClass : \'\'\n
};\n
\n
\n
$.noty.layouts.bottomLeft = {\n
    name     : \'bottomLeft\',\n
    options  : { // overrides options\n
\n
    },\n
    container: {\n
        object  : \'<ul id="noty_bottomLeft_layout_container" />\',\n
        selector: \'ul#noty_bottomLeft_layout_container\',\n
        style   : function() {\n
            $(this).css({\n
                bottom       : 20,\n
                left         : 20,\n
                position     : \'fixed\',\n
                width        : \'310px\',\n
                height       : \'auto\',\n
                margin       : 0,\n
                padding      : 0,\n
                listStyleType: \'none\',\n
                zIndex       : 10000000\n
            });\n
\n
            if(window.innerWidth < 600) {\n
                $(this).css({\n
                    left: 5\n
                });\n
            }\n
        }\n
    },\n
    parent   : {\n
        object  : \'<li />\',\n
        selector: \'li\',\n
        css     : {}\n
    },\n
    css      : {\n
        display: \'none\',\n
        width  : \'310px\'\n
    },\n
    addClass : \'\'\n
};\n
$.noty.layouts.bottomRight = {\n
    name     : \'bottomRight\',\n
    options  : { // overrides options\n
\n
    },\n
    container: {\n
        object  : \'<ul id="noty_bottomRight_layout_container" />\',\n
        selector: \'ul#noty_bottomRight_layout_container\',\n
        style   : function() {\n
            $(this).css({\n
                bottom       : 20,\n
                right        : 20,\n
                position     : \'fixed\',\n
                width        : \'310px\',\n
                height       : \'auto\',\n
                margin       : 0,\n
                padding      : 0,\n
                listStyleType: \'none\',\n
                zIndex       : 10000000\n
            });\n
\n
            if(window.innerWidth < 600) {\n
                $(this).css({\n
                    right: 5\n
                });\n
            }\n
        }\n
    },\n
    parent   : {\n
        object  : \'<li />\',\n
        selector: \'li\',\n
        css     : {}\n
    },\n
    css      : {\n
        display: \'none\',\n
        width  : \'310px\'\n
    },\n
    addClass : \'\'\n
};\n
$.noty.layouts.center = {\n
    name     : \'center\',\n
    options  : { // overrides options\n
\n
    },\n
    container: {\n
        object  : \'<ul id="noty_center_layout_container" />\',\n
        selector: \'ul#noty_center_layout_container\',\n
        style   : function() {\n
            $(this).css({\n
                position     : \'fixed\',\n
                width        : \'310px\',\n
                height       : \'auto\',\n
                margin       : 0,\n
                padding      : 0,\n
                listStyleType: \'none\',\n
                zIndex       : 10000000\n
            });\n
\n
            // getting hidden height\n
            var dupe = $(this).clone().css({visibility: "hidden", display: "block", position: "absolute", top: 0, left: 0}).attr(\'id\', \'dupe\');\n
            $("body").append(dupe);\n
            dupe.find(\'.i-am-closing-now\').remove();\n
            dupe.find(\'li\').css(\'display\', \'block\');\n
            var actual_height = dupe.height();\n
            dupe.remove();\n
\n
            if($(this).hasClass(\'i-am-new\')) {\n
                $(this).css({\n
                    left: ($(window).width() - $(this).outerWidth(false)) / 2 + \'px\',\n
                    top : ($(window).height() - actual_height) / 2 + \'px\'\n
                });\n
            }\n
            else {\n
                $(this).animate({\n
                    left: ($(window).width() - $(this).outerWidth(false)) / 2 + \'px\',\n
                    top : ($(window).height() - actual_height) / 2 + \'px\'\n
                }, 500);\n
            }\n
\n
        }\n
    },\n
    parent   : {\n
        object  : \'<li />\',\n
        selector: \'li\',\n
        css     : {}\n
    },\n
    css      : {\n
        display: \'none\',\n
        width  : \'310px\'\n
    },\n
    addClass : \'\'\n
};\n
$.noty.layouts.centerLeft = {\n
    name     : \'centerLeft\',\n
    options  : { // overrides options\n
\n
    },\n
    container: {\n
        object  : \'<ul id="noty_centerLeft_layout_container" />\',\n
        selector: \'ul#noty_centerLeft_layout_container\',\n
        style   : function() {\n
            $(this).css({\n
                left         : 20,\n
                position     : \'fixed\',\n
                width        : \'310px\',\n
                height       : \'auto\',\n
                margin       : 0,\n
                padding      : 0,\n
                listStyleType: \'none\',\n
                zIndex       : 10000000\n
            });\n
\n
            // getting hidden height\n
            var dupe = $(this).clone().css({visibility: "hidden", display: "block", position: "absolute", top: 0, left: 0}).attr(\'id\', \'dupe\');\n
            $("body").append(dupe);\n
            dupe.find(\'.i-am-closing-now\').remove();\n
            dupe.find(\'li\').css(\'display\', \'block\');\n
            var actual_height = dupe.height();\n
            dupe.remove();\n
\n
            if($(this).hasClass(\'i-am-new\')) {\n
                $(this).css({\n
                    top: ($(window).height() - actual_height) / 2 + \'px\'\n
                });\n
            }\n
            else {\n
                $(this).animate({\n
                    top: ($(window).height() - actual_height) / 2 + \'px\'\n
                }, 500);\n
            }\n
\n
            if(window.innerWidth < 600) {\n
                $(this).css({\n
                    left: 5\n
                });\n
            }\n
\n
        }\n
    },\n
    parent   : {\n
        object  : \'<li />\',\n
        selector: \'li\',\n
        css     : {}\n
    },\n
    css      : {\n
        display: \'none\',\n
        width  : \'310px\'\n
    },\n
    addClass : \'\'\n
};\n
\n
$.noty.layouts.centerRight = {\n
    name     : \'centerRight\',\n
    options  : { // overrides options\n
\n
    },\n
    container: {\n
        object  : \'<ul id="noty_centerRight_layout_container" />\',\n
        selector: \'ul#noty_centerRight_layout_container\',\n
        style   : function() {\n
            $(this).css({\n
                right        : 20,\n
                position     : \'fixed\',\n
                width        : \'310px\',\n
                height       : \'auto\',\n
                margin       : 0,\n
                padding      : 0,\n
                listStyleType: \'none\',\n
                zIndex       : 10000000\n
            });\n
\n
            // getting hidden height\n
            var dupe = $(this).clone().css({visibility: "hidden", display: "block", position: "absolute", top: 0, left: 0}).attr(\'id\', \'dupe\');\n
            $("body").append(dupe);\n
            dupe.find(\'.i-am-closing-now\').remove();\n
            dupe.find(\'li\').css(\'display\', \'block\');\n
            var actual_height = dupe.height();\n
            dupe.remove();\n
\n
            if($(this).hasClass(\'i-am-new\')) {\n
                $(this).css({\n
                    top: ($(window).height() - actual_height) / 2 + \'px\'\n
                });\n
            }\n
            else {\n
                $(this).animate({\n
                    top: ($(window).height() - actual_height) / 2 + \'px\'\n
                }, 500);\n
            }\n
\n
            if(window.innerWidth < 600) {\n
                $(this).css({\n
                    right: 5\n
                });\n
            }\n
\n
        }\n
    },\n
    parent   : {\n
        object  : \'<li />\',\n
        selector: \'li\',\n
        css     : {}\n
    },\n
    css      : {\n
        display: \'none\',\n
        width  : \'310px\'\n
    },\n
    addClass : \'\'\n
};\n
$.noty.layouts.inline = {\n
    name     : \'inline\',\n
    options  : {},\n
    container: {\n
        object  : \'<ul class="noty_inline_layout_container" />\',\n
        selector: \'ul.noty_inline_layout_container\',\n
        style   : function() {\n
            $(this).css({\n
                width        : \'100%\',\n
                height       : \'auto\',\n
                margin       : 0,\n
                padding      : 0,\n
                listStyleType: \'none\',\n
                zIndex       : 9999999\n
            });\n
        }\n
    },\n
    parent   : {\n
        object  : \'<li />\',\n
        selector: \'li\',\n
        css     : {}\n
    },\n
    css      : {\n
        display: \'none\'\n
    },\n
    addClass : \'\'\n
};\n
$.noty.layouts.top = {\n
    name     : \'top\',\n
    options  : {},\n
    container: {\n
        object  : \'<ul id="noty_top_layout_container" />\',\n
        selector: \'ul#noty_top_layout_container\',\n
        style   : function() {\n
            $(this).css({\n
                top          : 0,\n
                left         : \'5%\',\n
                position     : \'fixed\',\n
                width        : \'90%\',\n
                height       : \'auto\',\n
                margin       : 0,\n
                padding      : 0,\n
                listStyleType: \'none\',\n
                zIndex       : 9999999\n
            });\n
        }\n
    },\n
    parent   : {\n
        object  : \'<li />\',\n
        selector: \'li\',\n
        css     : {}\n
    },\n
    css      : {\n
        display: \'none\'\n
    },\n
    addClass : \'\'\n
};\n
$.noty.layouts.topCenter = {\n
    name     : \'topCenter\',\n
    options  : { // overrides options\n
\n
    },\n
    container: {\n
        object  : \'<ul id="noty_topCenter_layout_container" />\',\n
        selector: \'ul#noty_topCenter_layout_container\',\n
        style   : function() {\n
            $(this).css({\n
                top          : 20,\n
                left         : 0,\n
                position     : \'fixed\',\n
                width        : \'310px\',\n
                height       : \'auto\',\n
                margin       : 0,\n
                padding      : 0,\n
                listStyleType: \'none\',\n
                zIndex       : 10000000\n
            });\n
\n
            $(this).css({\n
                left: ($(window).width() - $(this).outerWidth(false)) / 2 + \'px\'\n
            });\n
        }\n
    },\n
    parent   : {\n
        object  : \'<li />\',\n
        selector: \'li\',\n
        css     : {}\n
    },\n
    css      : {\n
        display: \'none\',\n
        width  : \'310px\'\n
    },\n
    addClass : \'\'\n
};\n
\n
$.noty.layouts.topLeft = {\n
    name     : \'topLeft\',\n
    options  : { // overrides options\n
\n
    },\n
    container: {\n
        object  : \'<ul id="noty_topLeft_layout_container" />\',\n
        selector: \'ul#noty_topLeft_layout_container\',\n
        style   : function() {\n
            $(this).css({\n
                top          : 20,\n
                left         : 20,\n
                position     : \'fixed\',\n
                width        : \'310px\',\n
                height       : \'auto\',\n
                margin       : 0,\n
                padding      : 0,\n
                listStyleType: \'none\',\n
                zIndex       : 10000000\n
            });\n
\n
            if(window.innerWidth < 600) {\n
                $(this).css({\n
                    left: 5\n
                });\n
            }\n
        }\n
    },\n
    parent   : {\n
        object  : \'<li />\',\n
        selector: \'li\',\n
        css     : {}\n
    },\n
    css      : {\n
        display: \'none\',\n
        width  : \'310px\'\n
    },\n
    addClass : \'\'\n
};\n
$.noty.layouts.topRight = {\n
    name     : \'topRight\',\n
    options  : { // overrides options\n
\n
    },\n
    container: {\n
        object  : \'<ul id="noty_topRight_layout_container" />\',\n
        selector: \'ul#noty_topRight_layout_container\',\n
        style   : function() {\n
            $(this).css({\n
                top          : 20,\n
                right        : 20,\n
                position     : \'fixed\',\n
                width        : \'310px\',\n
                height       : \'auto\',\n
                margin       : 0,\n
                padding      : 0,\n
                listStyleType: \'none\',\n
                zIndex       : 10000000\n
            });\n
\n
            if(window.innerWidth < 600) {\n
                $(this).css({\n
                    right: 5\n
                });\n
            }\n
        }\n
    },\n
    parent   : {\n
        object  : \'<li />\',\n
        selector: \'li\',\n
        css     : {}\n
    },\n
    css      : {\n
        display: \'none\',\n
        width  : \'310px\'\n
    },\n
    addClass : \'\'\n
};\n
$.noty.themes.bootstrapTheme = {\n
    name: \'bootstrapTheme\',\n
    modal: {\n
        css: {\n
            position: \'fixed\',\n
            width: \'100%\',\n
            height: \'100%\',\n
            backgroundColor: \'#000\',\n
            zIndex: 10000,\n
            opacity: 0.6,\n
            display: \'none\',\n
            left: 0,\n
            top: 0\n
        }\n
    },\n
    style: function() {\n
\n
        var containerSelector = this.options.layout.container.selector;\n
        $(containerSelector).addClass(\'list-group\');\n
\n
        this.$closeButton.append(\'<span aria-hidden="true">&times;</span><span class="sr-only">Close</span>\');\n
        this.$closeButton.addClass(\'close\');\n
\n
        this.$bar.addClass( "list-group-item" ).css(\'padding\', \'0px\');\n
\n
        switch (this.options.type) {\n
            case \'alert\': case \'notification\':\n
                this.$bar.addClass( "list-group-item-info" );\n
                break;\n
            case \'warning\':\n
                this.$bar.addClass( "list-group-item-warning" );\n
                break;\n
            case \'error\':\n
                this.$bar.addClass( "list-group-item-danger" );\n
                break;\n
            case \'information\':\n
                this.$bar.addClass("list-group-item-info");\n
                break;\n
            case \'success\':\n
                this.$bar.addClass( "list-group-item-success" );\n
                break;\n
        }\n
\n
        this.$message.css({\n
            fontSize: \'13px\',\n
            lineHeight: \'16px\',\n
            textAlign: \'center\',\n
            padding: \'8px 10px 9px\',\n
            width: \'auto\',\n
            position: \'relative\'\n
        });\n
    },\n
    callback: {\n
        onShow: function() {  },\n
        onClose: function() {  }\n
    }\n
};\n
\n
\n
$.noty.themes.defaultTheme = {\n
    name    : \'defaultTheme\',\n
    helpers : {\n
        borderFix: function() {\n
            if(this.options.dismissQueue) {\n
                var selector = this.options.layout.container.selector + \' \' + this.options.layout.parent.selector;\n
                switch(this.options.layout.name) {\n
                    case \'top\':\n
                        $(selector).css({borderRadius: \'0px 0px 0px 0px\'});\n
                        $(selector).last().css({borderRadius: \'0px 0px 5px 5px\'});\n
                        break;\n
                    case \'topCenter\':\n
                    case \'topLeft\':\n
                    case \'topRight\':\n
                    case \'bottomCenter\':\n
                    case \'bottomLeft\':\n
                    case \'bottomRight\':\n
                    case \'center\':\n
                    case \'centerLeft\':\n
                    case \'centerRight\':\n
                    case \'inline\':\n
                        $(selector).css({borderRadius: \'0px 0px 0px 0px\'});\n
                        $(selector).first().css({\'border-top-left-radius\': \'5px\', \'border-top-right-radius\': \'5px\'});\n
                        $(selector).last().css({\'border-bottom-left-radius\': \'5px\', \'border-bottom-right-radius\': \'5px\'});\n
                        break;\n
                    case \'bottom\':\n
                        $(selector).css({borderRadius: \'0px 0px 0px 0px\'});\n
                        $(selector).first().css({borderRadius: \'5px 5px 0px 0px\'});\n
                        break;\n
                    default:\n
                        break;\n
                }\n
            }\n
        }\n
    },\n
    modal   : {\n
        css: {\n
            position       : \'fixed\',\n
            width          : \'100%\',\n
            height         : \'100%\',\n
            backgroundColor: \'#000\',\n
            zIndex         : 10000,\n
            opacity        : 0.6,\n
            display        : \'none\',\n
            left           : 0,\n
            top            : 0\n
        }\n
    },\n
    style   : function() {\n
\n
        this.$bar.css({\n
            overflow  : \'hidden\',\n
            background: "url(\'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABsAAAAoCAQAAAClM0ndAAAAhklEQVR4AdXO0QrCMBBE0bttkk38/w8WRERpdyjzVOc+HxhIHqJGMQcFFkpYRQotLLSw0IJ5aBdovruMYDA/kT8plF9ZKLFQcgF18hDj1SbQOMlCA4kao0iiXmah7qBWPdxpohsgVZyj7e5I9KcID+EhiDI5gxBYKLBQYKHAQoGFAoEks/YEGHYKB7hFxf0AAAAASUVORK5CYII=\') repeat-x scroll left top #fff"\n
        });\n
\n
        this.$message.css({\n
            fontSize  : \'13px\',\n
            lineHeight: \'16px\',\n
            textAlign : \'center\',\n
            padding   : \'8px 10px 9px\',\n
            width     : \'auto\',\n
            position  : \'relative\'\n
        });\n
\n
        this.$closeButton.css({\n
            position  : \'absolute\',\n
            top       : 4, right: 4,\n
            width     : 10, height: 10,\n
            background: "url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAQAAAAnOwc2AAAAxUlEQVR4AR3MPUoDURSA0e++uSkkOxC3IAOWNtaCIDaChfgXBMEZbQRByxCwk+BasgQRZLSYoLgDQbARxry8nyumPcVRKDfd0Aa8AsgDv1zp6pYd5jWOwhvebRTbzNNEw5BSsIpsj/kurQBnmk7sIFcCF5yyZPDRG6trQhujXYosaFoc+2f1MJ89uc76IND6F9BvlXUdpb6xwD2+4q3me3bysiHvtLYrUJto7PD/ve7LNHxSg/woN2kSz4txasBdhyiz3ugPGetTjm3XRokAAAAASUVORK5CYII=)",\n
            display   : \'none\',\n
            cursor    : \'pointer\'\n
        });\n
\n
        this.$buttons.css({\n
            padding        : 5,\n
            textAlign      : \'right\',\n
            borderTop      : \'1px solid #ccc\',\n
            backgroundColor: \'#fff\'\n
        });\n
\n
        this.$buttons.find(\'button\').css({\n
            marginLeft: 5\n
        });\n
\n
        this.$buttons.find(\'button:first\').css({\n
            marginLeft: 0\n
        });\n
\n
        this.$bar.on({\n
            mouseenter: function() {\n
                $(this).find(\'.noty_close\').stop().fadeTo(\'normal\', 1);\n
            },\n
            mouseleave: function() {\n
                $(this).find(\'.noty_close\').stop().fadeTo(\'normal\', 0);\n
            }\n
        });\n
\n
        switch(this.options.layout.name) {\n
            case \'top\':\n
                this.$bar.css({\n
                    borderRadius: \'0px 0px 5px 5px\',\n
                    borderBottom: \'2px solid #eee\',\n
                    borderLeft  : \'2px solid #eee\',\n
                    borderRight : \'2px solid #eee\',\n
                    boxShadow   : "0 2px 4px rgba(0, 0, 0, 0.1)"\n
                });\n
                break;\n
            case \'topCenter\':\n
            case \'center\':\n
            case \'bottomCenter\':\n
            case \'inline\':\n
                this.$bar.css({\n
                    borderRadius: \'5px\',\n
                    border      : \'1px solid #eee\',\n
                    boxShadow   : "0 2px 4px rgba(0, 0, 0, 0.1)"\n
                });\n
                this.$message.css({fontSize: \'13px\', textAlign: \'center\'});\n
                break;\n
            case \'topLeft\':\n
            case \'topRight\':\n
            case \'bottomLeft\':\n
            case \'bottomRight\':\n
            case \'centerLeft\':\n
            case \'centerRight\':\n
                this.$bar.css({\n
                    borderRadius: \'5px\',\n
                    border      : \'1px solid #eee\',\n
                    boxShadow   : "0 2px 4px rgba(0, 0, 0, 0.1)"\n
                });\n
                this.$message.css({fontSize: \'13px\', textAlign: \'left\'});\n
                break;\n
            case \'bottom\':\n
                this.$bar.css({\n
                    borderRadius: \'5px 5px 0px 0px\',\n
                    borderTop   : \'2px solid #eee\',\n
                    borderLeft  : \'2px solid #eee\',\n
                    borderRight : \'2px solid #eee\',\n
                    boxShadow   : "0 -2px 4px rgba(0, 0, 0, 0.1)"\n
                });\n
                break;\n
            default:\n
                this.$bar.css({\n
                    border   : \'2px solid #eee\',\n
                    boxShadow: "0 2px 4px rgba(0, 0, 0, 0.1)"\n
                });\n
                break;\n
        }\n
\n
        switch(this.options.type) {\n
            case \'alert\':\n
            case \'notification\':\n
                this.$bar.css({backgroundColor: \'#FFF\', borderColor: \'#CCC\', color: \'#444\'});\n
                break;\n
            case \'warning\':\n
                this.$bar.css({backgroundColor: \'#FFEAA8\', borderColor: \'#FFC237\', color: \'#826200\'});\n
                this.$buttons.css({borderTop: \'1px solid #FFC237\'});\n
                break;\n
            case \'error\':\n
                this.$bar.css({backgroundColor: \'red\', borderColor: \'darkred\', color: \'#FFF\'});\n
                this.$message.css({fontWeight: \'bold\'});\n
                this.$buttons.css({borderTop: \'1px solid darkred\'});\n
                break;\n
            case \'information\':\n
                this.$bar.css({backgroundColor: \'#57B7E2\', borderColor: \'#0B90C4\', color: \'#FFF\'});\n
                this.$buttons.css({borderTop: \'1px solid #0B90C4\'});\n
                break;\n
            case \'success\':\n
                this.$bar.css({backgroundColor: \'lightgreen\', borderColor: \'#50C24E\', color: \'darkgreen\'});\n
                this.$buttons.css({borderTop: \'1px solid #50C24E\'});\n
                break;\n
            default:\n
                this.$bar.css({backgroundColor: \'#FFF\', borderColor: \'#CCC\', color: \'#444\'});\n
                break;\n
        }\n
    },\n
    callback: {\n
        onShow : function() {\n
            $.noty.themes.defaultTheme.helpers.borderFix.apply(this);\n
        },\n
        onClose: function() {\n
            $.noty.themes.defaultTheme.helpers.borderFix.apply(this);\n
        }\n
    }\n
};\n
\n
$.noty.themes.relax = {\n
    name    : \'relax\',\n
    helpers : {},\n
    modal   : {\n
        css: {\n
            position       : \'fixed\',\n
            width          : \'100%\',\n
            height         : \'100%\',\n
            backgroundColor: \'#000\',\n
            zIndex         : 10000,\n
            opacity        : 0.6,\n
            display        : \'none\',\n
            left           : 0,\n
            top            : 0\n
        }\n
    },\n
    style   : function() {\n
\n
        this.$bar.css({\n
            overflow    : \'hidden\',\n
            margin      : \'4px 0\',\n
            borderRadius: \'2px\'\n
        });\n
\n
        this.$message.css({\n
            fontSize  : \'14px\',\n
            lineHeight: \'16px\',\n
            textAlign : \'center\',\n
            padding   : \'10px\',\n
            width     : \'auto\',\n
            position  : \'relative\'\n
        });\n
\n
        this.$closeButton.css({\n
            position  : \'absolute\',\n
            top       : 4, right: 4,\n
            width     : 10, height: 10,\n
            background: "url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAQAAAAnOwc2AAAAxUlEQVR4AR3MPUoDURSA0e++uSkkOxC3IAOWNtaCIDaChfgXBMEZbQRByxCwk+BasgQRZLSYoLgDQbARxry8nyumPcVRKDfd0Aa8AsgDv1zp6pYd5jWOwhvebRTbzNNEw5BSsIpsj/kurQBnmk7sIFcCF5yyZPDRG6trQhujXYosaFoc+2f1MJ89uc76IND6F9BvlXUdpb6xwD2+4q3me3bysiHvtLYrUJto7PD/ve7LNHxSg/woN2kSz4txasBdhyiz3ugPGetTjm3XRokAAAAASUVORK5CYII=)",\n
            display   : \'none\',\n
            cursor    : \'pointer\'\n
        });\n
\n
        this.$buttons.css({\n
            padding        : 5,\n
            textAlign      : \'right\',\n
            borderTop      : \'1px solid #ccc\',\n
            backgroundColor: \'#fff\'\n
        });\n
\n
        this.$buttons.find(\'button\').css({\n
            marginLeft: 5\n
        });\n
\n
        this.$buttons.find(\'button:first\').css({\n
            marginLeft: 0\n
        });\n
\n
        this.$bar.on({\n
            mouseenter: function() {\n
                $(this).find(\'.noty_close\').stop().fadeTo(\'normal\', 1);\n
            },\n
            mouseleave: function() {\n
                $(this).find(\'.noty_close\').stop().fadeTo(\'normal\', 0);\n
            }\n
        });\n
\n
        switch(this.options.layout.name) {\n
            case \'top\':\n
                this.$bar.css({\n
                    borderBottom: \'2px solid #eee\',\n
                    borderLeft  : \'2px solid #eee\',\n
                    borderRight : \'2px solid #eee\',\n
                    borderTop   : \'2px solid #eee\',\n
                    boxShadow   : "0 2px 4px rgba(0, 0, 0, 0.1)"\n
                });\n
                break;\n
            case \'topCenter\':\n
            case \'center\':\n
            case \'bottomCenter\':\n
            case \'inline\':\n
                this.$bar.css({\n
                    border   : \'1px solid #eee\',\n
                    boxShadow: "0 2px 4px rgba(0, 0, 0, 0.1)"\n
                });\n
                this.$message.css({fontSize: \'13px\', textAlign: \'center\'});\n
                break;\n
            case \'topLeft\':\n
            case \'topRight\':\n
            case \'bottomLeft\':\n
            case \'bottomRight\':\n
            case \'centerLeft\':\n
            case \'centerRight\':\n
                this.$bar.css({\n
                    border   : \'1px solid #eee\',\n
                    boxShadow: "0 2px 4px rgba(0, 0, 0, 0.1)"\n
                });\n
                this.$message.css({fontSize: \'13px\', textAlign: \'left\'});\n
                break;\n
            case \'bottom\':\n
                this.$bar.css({\n
                    borderTop   : \'2px solid #eee\',\n
                    borderLeft  : \'2px solid #eee\',\n
                    borderRight : \'2px solid #eee\',\n
                    borderBottom: \'2px solid #eee\',\n
                    boxShadow   : "0 -2px 4px rgba(0, 0, 0, 0.1)"\n
                });\n
                break;\n
            default:\n
                this.$bar.css({\n
                    border   : \'2px solid #eee\',\n
                    boxShadow: "0 2px 4px rgba(0, 0, 0, 0.1)"\n
                });\n
                break;\n
        }\n
\n
        switch(this.options.type) {\n
            case \'alert\':\n
            case \'notification\':\n
                this.$bar.css({backgroundColor: \'#FFF\', borderColor: \'#dedede\', color: \'#444\'});\n
                break;\n
            case \'warning\':\n
                this.$bar.css({backgroundColor: \'#FFEAA8\', borderColor: \'#FFC237\', color: \'#826200\'});\n
                this.$buttons.css({borderTop: \'1px solid #FFC237\'});\n
                break;\n
            case \'error\':\n
                this.$bar.css({backgroundColor: \'#FF8181\', borderColor: \'#e25353\', color: \'#FFF\'});\n
                this.$message.css({fontWeight: \'bold\'});\n
                this.$buttons.css({borderTop: \'1px solid darkred\'});\n
                break;\n
            case \'information\':\n
                this.$bar.css({backgroundColor: \'#78C5E7\', borderColor: \'#3badd6\', color: \'#FFF\'});\n
                this.$buttons.css({borderTop: \'1px solid #0B90C4\'});\n
                break;\n
            case \'success\':\n
                this.$bar.css({backgroundColor: \'#BCF5BC\', borderColor: \'#7cdd77\', color: \'darkgreen\'});\n
                this.$buttons.css({borderTop: \'1px solid #50C24E\'});\n
                break;\n
            default:\n
                this.$bar.css({backgroundColor: \'#FFF\', borderColor: \'#CCC\', color: \'#444\'});\n
                break;\n
        }\n
    },\n
    callback: {\n
        onShow : function() {\n
\n
        },\n
        onClose: function() {\n
\n
        }\n
    }\n
};\n
\n
\n
return window.noty;\n
\n
});

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>46571</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
