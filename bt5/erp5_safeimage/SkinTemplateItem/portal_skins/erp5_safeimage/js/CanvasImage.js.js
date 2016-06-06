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
            <value> <string>ts54116840.51</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>CanvasImage.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/* Copyright (c) 2006-2008 MetaCarta, Inc., published under the Clear BSD\n
 * license.  See http://svn.openlayers.org/trunk/openlayers/license.txt for the\n
 * full text of the license. */\n
\n
\n
/**\n
 * @requires OpenLayers/Tile.js\n
 */\n
\n
/**\n
 * Class: OpenLayers.Tile.CanvasImage\n
 * Instances of OpenLayers.Tile.CanvasImage are used to manage the image tiles\n
 * used by various layers.  Create a new image tile with the\n
 * <OpenLayers.Tile.CanvasImage> constructor.\n
 *\n
 * Inherits from:\n
 *  - <OpenLayers.Tile>\n
 */\n
OpenLayers.Tile.CanvasImage = OpenLayers.Class(OpenLayers.Tile, {\n
\n
    /** \n
     * Property: url\n
     * {String} The URL of the image being requested. No default. Filled in by\n
     * layer.getURL() function. \n
     */\n
    url: null,\n
    \n
    /** \n
     * Property: canvasType\n
     * {OpenLayers.Layer.Grid.ONECANVASPERLAYER|\n
     * OpenLayers.Layer.Grid.ONECANVASPERTILE} One canvas element per layer or per tile?\n
     */    \n
    canvasType: null,\n
    \n
    /**\n
     * APIProperty: crossOriginKeyword\n
     * The value of the crossorigin keyword to use when loading images. This is\n
     * only relevant when using <getCanvasContext> for tiles from remote\n
     * origins and should be set to either \'anonymous\' or \'use-credentials\'\n
     * for servers that send Access-Control-Allow-Origin headers with their\n
     * tiles.\n
     */\n
    crossOriginKeyword: null,\n
    /**\n
     * APIProperty: crossOriginKeyword\n
     * The value of the crossorigin keyword to use when loading images. This is\n
     * only relevant when using <getCanvasContext> for tiles from remote\n
     * origins and should be set to either \'anonymous\' or \'use-credentials\'\n
     * for servers that send Access-Control-Allow-Origin headers with their\n
     * tiles.\n
     */\n
    crossOriginKeyword: null,\n
\n
\n
    /**\n
     * Property: frame\n
     * {DOMElement} The canvas element is appended to the frame.  Any gutter on\n
     * the canvas will be hidden behind the frame. \n
     */ \n
    frame: null,\n
    \n
    /**\n
     * Property: isLoading\n
     * {Boolean} Indicates if the tile is currently waiting on a loading image. \n
     */ \n
    isLoading: false,\n
    \n
    /** \n
     * Property: canvas\n
     * {DOMElement} The canvas element on which the image is drawn.\n
     */\n
    canvas: null,\n
    \n
    /** \n
     * Property: canvasImageData\n
     * {ImageData} The ImageData object for the canvas.\n
     */\n
    canvasImageData: null,\n
    \n
    /** \n
     * Property: lastImage\n
     * {Image} The last requested image object. This property is used to make sure\n
     *      that only the recent image is drawn.\n
     */\n
    lastImage: null,\n
    \n
    /** \n
     * Property: lastBounds\n
     * {<OpenLayers.Bounds>} The bounds of the last requested image, needed for \n
     *      VirtualCanvasImage.displayImage().\n
     */\n
    lastBounds: null,\n
    \n
    /**\n
     * Property: isBackBuffer\n
     * {Boolean} Is this tile a back buffer tile?\n
     */\n
    isBackBuffer: false,\n
        \n
    /**\n
     * Property: backBufferTile\n
     * {<OpenLayers.Tile>} A clone of the tile used to create transition\n
     *     effects when the tile is moved or changes resolution.\n
     */\n
    backBufferTile: null,\n
\n
    /**\n
      *Property. transforms\n
      *JSON file where the transforms are written\n
      *\n
      */\n
    transforms: null,\n
\n
    /** \n
      *Property partialTile\n
    */\n
    partialTile: null,\n
\n
    /**\n
      *Propperty partialId\n
      */\n
\n
    partialId: null,\n
\n
    /**\n
      *Property partialAlgorithm\n
      */\n
    partialAlgorithm: null,\n
    \n
       \n
    /**\n
      *Property partialParam1\n
      */\n
    partialParam1: null,\n
\n
    /**\n
      *Property partialParam2\n
      */\n
    partialParam2: null,\n
\n
    /**\n
      *Property partialNum\n
      */\n
    partialNum: 0,\n
\n
    /** TBD 3.0 - reorder the parameters to the init function to remove \n
     *             URL. the getUrl() function on the layer gets called on \n
     *             each draw(), so no need to specify it here.\n
     * \n
     * Constructor: OpenLayers.Tile.Image\n
     * Constructor for a new <OpenLayers.Tile.Image> instance.\n
     * \n
     * Parameters:\n
     * layer - {<OpenLayers.Layer>} layer that the tile will go in.\n
     * position - {<OpenLayers.Pixel>}\n
     * bounds - {<OpenLayers.Bounds>}\n
     * url - {<String>} Deprecated. Remove me in 3.0.\n
     * size - {<OpenLayers.Size>}\n
     * canvasType - {<OpenLayers.Layer.Grid.ONECANVASPERLAYER|OpenLayers.Layer.Grid.ONECANVASPERTILE>}\n
     */   \n
    initialize: function(layer, position, bounds, url, size,transforms, canvasType) {\n
        OpenLayers.Tile.prototype.initialize.apply(this, arguments);\n
        this.url = url; //deprecated remove me\n
        this.canvasType = canvasType;\n
        this.frame = document.createElement(\'div\'); \n
        this.frame.style.overflow = \'hidden\'; \n
        this.frame.style.position = \'absolute\'; \n
        this.transforms = transforms;        \n
        this.events.addEventType("reprojectionProgress");\n
        this.events.addEventType("filterProgress");\n
    },\n
\n
    /** \n
     * APIMethod: destroy\n
     * nullify references to prevent circular references and memory leaks\n
     */\n
    destroy: function() {\n
        if ((this.frame != null) && (this.frame.parentNode == this.layer.div)) {\n
            this.layer.div.removeChild(this.frame);\n
        }\n
        this.frame = null;\n
        this.lastImage = null;\n
        this.canvas = null;\n
        this.canvasContext = null;\n
        // clean up the backBufferTile if it exists\n
        if (this.backBufferTile) {\n
            this.backBufferTile.destroy();\n
            this.backBufferTile = null;\n
            this.layer.events.unregister("loadend", this, this.hideBackBuffer);\n
        }        \n
        OpenLayers.Tile.prototype.destroy.apply(this, arguments);\n
    },\n
\n
    /**\n
     * Method: clone\n
     *\n
     * Parameters:\n
     * obj - {<OpenLayers.Tile.Image>} The tile to be cloned\n
     *\n
     * Returns:\n
     * {<OpenLayers.Tile.Image>} An exact clone of this <OpenLayers.Tile.Image>\n
     */\n
    clone: function (obj) {\n
        if (obj == null) {\n
            obj = new OpenLayers.Tile.CanvasImage(this.layer, \n
                                            this.position, \n
                                            this.bounds, \n
                                            this.url, \n
                                            this.size,\n
                                            this.canvasType);        \n
        } \n
        \n
        //pick up properties from superclass\n
        obj = OpenLayers.Tile.prototype.clone.apply(this, [obj]);\n
        \n
        // a new canvas element should be created for the clone\n
        obj.canvas = null;\n
        \n
        return obj;\n
    },\n
    \n
    /**\n
     * Method: draw\n
     * Check that a tile should be drawn, and draw it. Starts a\n
     * transition if the layer requests one.\n
     * \n
     * Returns:\n
     * {Boolean} Always returns true.\n
     */\n
    draw: function() {\n
        if (this.layer != this.layer.map.baseLayer && this.layer.reproject) {\n
            this.bounds = this.getBoundsFromBaseLayer(this.position);\n
        }\n
        var drawTile = OpenLayers.Tile.prototype.draw.apply(this, arguments);\n
        \n
        if (this.layer.usesTransition()) {\n
           this.startTransition(drawTile);\n
        }\n
       \n
        if (!drawTile) {\n
          return;\n
        }\n
        \n
        if (this.isLoading) {\n
            // if we\'re already loading, send \'reload\' instead of \'loadstart\'.\n
            this.events.triggerEvent("reload"); \n
        } else {\n
            this.isLoading = true;\n
            this.events.triggerEvent("loadstart");\n
        }\n
        return this.renderTile();  \n
    },\n
    \n
    /**\n
     * Method: renderTile\n
     * Creates the canvas element and sets the URL.\n
     * \n
     * Returns:\n
     * {Boolean} Always returns true.\n
     */\n
    renderTile: function() {\n
        if (this.canvas === null) {\n
            this.initCanvas();\n
        }    \n
        \n
        if (this.layer.async) {\n
            // Asyncronous image requests call the asynchronous getURL method\n
            // on the layer to fetch an image that covers \'this.bounds\', in the scope of\n
            // \'this\', setting the \'url\' property of the layer itself, and running\n
            // the callback \'positionFrame\' when the image request returns.\n
             this.layer.getURLasync(this.bounds, this, "url", this.positionImage);\n
        } else {\n
            // syncronous image requests get the url and position the frame immediately,\n
            // and don\'t wait for an image request to come back.\n
          \n
          // todo: use different image url for retry, see Util.OpenLayers.Util.onImageLoadError\n
          \n
//            // needed for changing to a different server for onload error\n
//            if (this.layer.url instanceof Array) {\n
//                this.imgDiv.urls = this.layer.url.slice();\n
//            }\n
            this.url = this.layer.getURL(this.bounds);\n
          \n
            // position the frame immediately\n
            this.positionImage(); \n
        }\n
        \n
        return true;\n
    },\n
    \n
    /**\n
     * Method: initCanvas\n
     * Creates the canvas element and appends it to the tile\'s frame.\n
     */\n
    initCanvas: function() {\n
        var offset = this.layer.imageOffset;\n
        var size = this.layer.getImageSize(this.bounds);\n
\n
        // set the opacity on the tile\'s frame\n
        if(this.layer.opacity != null) {\n
            OpenLayers.Util.modifyDOMElement(this.frame, null, null, null,\n
                                             null, null, null, \n
                                             this.layer.opacity);\n
        }\n
        \n
        this.canvas = document.createElement("canvas");\n
        this.canvasContext = this.canvas.getContext(\'2d\'); \n
        this.canvas.width = this.size.w;\n
        this.canvas.height = this.size.h;\n
        this.frame.appendChild(this.canvas);\n
        \n
        var id = OpenLayers.Util.createUniqueID("OpenLayersCanvas");\n
        OpenLayers.Util.modifyDOMElement(this.canvas, id, offset, size, "relative", null, null, true);\n
        \n
        this.layer.div.appendChild(this.frame);        \n
    },\n
    \n
    /**\n
     * Method: positionImage\n
     * Sets the position and size of the tile\'s frame and\n
     * canvas element.\n
     */\n
    positionImage: function() {\n
        // if the this layer doesn\'t exist at the point the image is\n
        // returned, do not attempt to use it for size computation\n
      if(this.layer == null) {\n
            return;\n
        }           \n
        \n
        // position the frame \n
        OpenLayers.Util.modifyDOMElement(this.frame, \n
                                      null, this.position, this.size);   \n
        \n
        // and then update the canvas size // todo: yes?   \n
        var size = this.layer.getImageSize(this.bounds); // difference between this.size and size?                           \n
        OpenLayers.Util.modifyDOMElement(this.canvas, null, null, size);    \n
           \n
        this.createImage();\n
    },\n
\n
    /**\n
     * Method: createImage\n
     * Creates the image and starts loading it.\n
     */\n
    createImage: function() {\n
        // first cancel loading the last image\n
        if (this.lastImage !== null && !this.lastImage.complete) {\n
            // note that this doesn\'t cancel loading for WebKit, see https://bugs.webkit.org/show_bug.cgi?id=35377\n
            this.lastImage.src = \'\';\n
        }\n
        \n
        var image = new Image();    \n
        this.lastImage = image;\n
        this.lastBounds = this.bounds.clone();\n
        var context = { \n
            image: image,\n
            tile: this,\n
            viewRequestID: this.layer.map.viewRequestID,\n
            data: null,\n
            bounds: this.bounds.clone() // todo: do we still need the bounds? guess no\n
            //urls: this.layer.url.slice() // todo: for retries?\n
        };        \n
        \n
        var onLoadFunctionProxy = function() {\n
            this.tile.onLoadFunction(this);    \n
        };\n
        \n
        var onErrorFunctionProxy = function() {\n
            this.tile.onErrorFunction(this);\n
        };\n
       \n
        var can = document.createElement("canvas");\n
\n
        var process = false;\n
        var that = this;\n
          \n
             //onLoadFunctionProxy;\n
        image.onerror = OpenLayers.Function.bind(onErrorFunctionProxy, context);\n
        image.crossOrigin = ""; \n
        image.src = this.url;\n
        this.getId();\n
        image.onload = OpenLayers.Function.bind(onLoadFunctionProxy,context);\n
   },\n
    \n
     /**\n
        Method: getId\n
       * Used to catch the tile-group and tileid from JSON file\n
      */\n
    \n
    getId: function(){\n
       aux = this.url.split(\'/\');\n
       jpg = aux[7].split(\'.\');\n
       this.partialTile = aux[6];\n
       this.partialId = jpg[0];\n
    },\n
\n
    /**\n
     * Method: onLoadFunction\n
     * Called when an image successfully finished loading. Draws the\n
     * image on the canvas.\n
     * \n
     * Parameters:\n
     * context - {<Object>} The context from the onload event.\n
     */\n
    onLoadFunction: function(context) {\n
        if ((this.layer === null) ||\n
                (context.viewRequestID !== this.layer.map.viewRequestID) ||\n
                (context.image !== this.lastImage)) {\n
            return;\n
        }   \n
        var image = context.image;\n
        var data = context.data;\n
        \n
        if (this.layer.projection.getCode() != this.layer.map.getProjection()) {\n
            // reproject image\n
            var sourceCRS = this.layer.projection;\n
            var targetCRS = this.layer.map.projection;\n
            var sourceBounds = this.layer.getReprojectedBounds(this.bounds);\n
            var targetBounds = this.bounds;\n
            var sourceSize = new OpenLayers.Size(image.width, image.height);\n
            var targetSize = this.layer.getImageSize(this.bounds);\n
            image = this.reproject(image, sourceCRS, sourceBounds, sourceSize, \n
                                    targetCRS, targetBounds, targetSize);            \n
        } else {\n
            this.displayImage(image);\n
        }\n
    },\n
    \n
    /**\n
     * Method: displayImage\n
     * Takes care of resizing the canvas and then draws the \n
     * canvas.\n
     * \n
     * Parameters:\n
     * image - {Image/Canvas} The image to display\n
     */\n
    displayImage: function(image) {\n
        if (this.layer.canvasFilter && !image.filtered) {\n
            // if a filter is set, apply the filter first and\n
            // then use the result\n
            this.filter(image);\n
            return;\n
        } \n
        \n
        // reset canvas (for transparent tiles)\n
        var size = this.layer.getImageSize(this.bounds);\n
        this.canvas.width = size.w;\n
        this.canvas.height = size.h;\n
        \n
        // when using a backbuffer, force the original tile on top\n
        var bringToTop = (this.backBufferTile !== null);\n
        \n
        // draw the image on the canvas\n
        this.drawImage(image, null, bringToTop);\n
        this.canvasImageData = null;\n
        \n
        if (this.backBufferTile) {\n
          this.setBackBuffer(image);\n
        }   \n
        this.isLoading = false; \n
        this.events.triggerEvent("loadend"); \n
    },\n
    \n
    /**\n
     * Method: drawImage\n
     * Draws the image on the canvas and scales the image\n
     * if required.\n
     * \n
     * Parameters:\n
     * image - {<Image>} The image to draw\n
     * size - {<OpenLayers.Size>} The target size of the image\n
     * brintToTop - {<Boolean>} Should the tile\'s frame be forced to be on top?\n
     */\n
    drawImage: function(image, size, bringToTop) {\n
       \n
        /* canvas_clean created to avoid canvas "dirty" issue */\n
        try{\n
              var canvas_clean = document.createElement(\'canvas\'); \n
        }catch(ex){\n
              console.log("Canvas NOT SUPPORTED");\n
        }\n
            canvas_clean.width = image.width;\n
            canvas_clean.height = image.height;\n
            this.canvas.width = image.width;\n
            this.canvas.height = image.height;\n
            ctx = canvas_clean.getContext("2d");          \n
            ctx.drawImage(image,0,0,image.width,image.height);\n
        try{      \n
            data= ctx.getImageData(0,0,image.width,image.height);\n
        }catch(ex){\n
            console.log(ex);\n
        } \n
       /* variable repeat is used to assure that differents algorithms could be \n
        applied in the same tile. In the future should be modified.*/\n
       var repeat = 0;\n
       this.findParams(repeat);\n
       x = this.applyAlgorithm(data,image.width,image.height);\n
       while(this.partialNum > 0){\n
           repeat = 1;\n
           this.partialNum = this.partialNum-1;\n
           this.findParams(repeat);\n
           x = this.applyAlgorithm(x,image.width,image.height);\n
           repeat--;\n
      }\n
 \n
      try {\n
          if (size !== null) {\n
             this.canvasContext.putImageData(x,image.width,image.height);\n
          }else {\n
             this.canvasContext.putImageData(x, 0, 0);\n
          }\n
          if (bringToTop) {\n
             this.layer.div.removeChild(this.frame);\n
             this.layer.div.appendChild(this.frame);\n
          }\n
            this.display();\n
      } \n
      catch (exc) {\n
        console.log(\'drawImage failed: \' + ((image) ? image.src : image)); // todo\n
        this.clear();\n
      }   \n
    },\n
\n
    /**\n
      * Method: findParams\n
        Get the parameters from JSON \n
        transform file.         \n
      */\n
     findParams: function(repeat){\n
         var length = this.transforms.length;\n
         var again = repeat;\n
         \n
         for(i=0; i<length;i++){\n
           if(again == 0){\n
             if((this.transforms[i]["tileid"] === this.partialId) && \n
                                (this.transforms[i]["tilegroup"] === this.partialTile)){\n
               this.partialAlgorithm =this.transforms[i]["algorithm"];\n
               this.partialParam1 = this.transforms[i]["param1"];\n
               this.partialParam2 = this.transforms[i]["param2"];\n
               this.partialNum = this.transforms[i]["num"];\n
               break;\n
             }\n
            }else{\n
              if((this.transforms[i]["tileid"] === this.partialId) && \n
                              (this.transforms[i]["tilegroup"] === this.partialTile)){\n
                if(this.transforms[i]["num"] === this.partialNum){\n
                  this.partialAlgorithm =this.transforms[i]["algorithm"];\n
                  this.partialParam1 = this.transforms[i]["param1"];\n
                  this.partialParam2 = this.transforms[i]["param2"];\n
                  break;\n
                } \n
              }\n
           }\n
         }\n
      }, \n
\n
    /**\n
      *Method: applyAlgorithm\n
           Called to process the data\n
      */\n
      applyAlgorithm: function(data,width,height){\n
          switch(this.partialAlgorithm){\n
              case \'sepia\':\n
                  return sepia(data,width,height);\n
              case \'brightness\':\n
                  return brightness(data,width,height,this.partialParam1,this.partialParam2);\n
              case \'noise\':\n
                  return noise(data,width,height);\n
              case \'posterize\':\n
                  return posterize(data,width,height,this.partialParam1);\n
              case \'edge\':\n
                  return edges(data,width,height);\n
              case \'lighten\':\n
                  return lighten(data,width,height,this.partialParam1);\n
              default:\n
                  return data;\n
          }                  \n
      },\n
\n
    /**\n
     * Method: onErrorFunction\n
     * Called when an image finished loading, but not successfully. \n
     * \n
     * Parameters:\n
     * context - {<Object>} The context from the onload event.\n
     */    \n
    onErrorFunction: function(context) {\n
        if (context.image !== this.lastImage) {\n
            /* Do not trigger \'loadend\' when a new image was request\n
             * for this tile, because then \'reload\' was triggered instead\n
             * of \'loadstart\'.\n
             * If we would trigger \'loadend\' now, Grid would get confused about\n
             * its \'numLoadingTiles\'.\n
             */\n
            return;\n
        }\n
    \t\n
        // retry? with different url?    \n
        console.log(this.id + \' onErrorFunction: \' + context.image.src); // todo\n
        this.events.triggerEvent("loadend");\n
    },\n
    \n
    /** \n
     * Method: clear\n
     * Clear the tile of any bounds/position-related data so that it can \n
     *     be reused in a new location. Called in <OpenLayers.Tile.draw()>.\n
     */\n
    clear: function() {\n
        // to be implemented by subclasses\n
        if (this.frame !== null) {\n
            this.frame.style.display = \'none\';\n
        }\n
    },\n
    \n
    /** \n
     * Method: display\n
     * Display the tile.\n
     */\n
    display: function() {\n
        // to be implemented by subclasses\n
        if (this.frame !== null) {\n
            this.frame.style.display = \'\';\n
        }\n
    },\n
    \n
    /** \n
     * Method: show\n
     * Show the tile. Called in <OpenLayers.Tile.showTile()>.\n
     */\n
    show: function() {},\n
    \n
    /** \n
     * Method: hide\n
     * Hide the tile.  To be implemented by subclasses (but never called).\n
     */\n
    hide: function() { },\n
    \n
    /**\n
     * Method: startTransition\n
     * Creates a backbuffer tile (if it does not exist already)\n
     * and then displays this tile. \n
     * \n
     * Parameters:\n
     * drawTile - {<Boolean>} Should the tile be drawn?\n
     */\n
    startTransition: function(drawTile) {\n
       if (drawTile) {\n
            //we use a clone of this tile to create a double buffer for visual\n
            //continuity.  The backBufferTile is used to create transition\n
            //effects while the tile in the grid is repositioned and redrawn\n
            if (!this.backBufferTile) {\n
                this.createBackBufferTile();\n
            }\n
            // run any transition effects\n
            this.showBackBufferTile();\n
        } else {\n
            // if we aren\'t going to draw the tile, then the backBuffer should\n
            // be hidden too!\n
            if (this.backBufferTile) {\n
                this.backBufferTile.clear();\n
            }\n
        }        \n
    },\n
    \n
    /**\n
     * Method: createBackBufferTile\n
     * Create a backbuffer tile from the current tile.\n
     */\n
    createBackBufferTile: function() {\n
        this.backBufferTile = this.clone();\n
        \n
        this.backBufferTile.clear();\n
        this.backBufferTile.isBackBuffer = true;\n
        this.backBufferTile.initCanvas();\n
        \n
        // clear transition back buffer tile only after all tiles in\n
        // this layer have loaded to avoid visual glitches\n
        this.layer.events.register("loadend", this, this.hideBackBuffer);       \n
    },\n
    \n
    /**\n
     * Method: setBackBuffer\n
     * Stores the loaded image in the backbuffer tile,\n
     * so that it can be used for the next request.\n
     * \n
     * Parameters:\n
     * image - {<Image>} The image to use as backbuffer\n
     */\n
    setBackBuffer: function(image) {\n
        if (this.backBufferTile) {\n
            // store the image, its position, resolution and bounds\n
            this.backBufferTile.lastImage = image;\n
            this.backBufferTile.position = this.position;\n
            this.backBufferTile.bounds = this.bounds;\n
            this.backBufferTile.size = this.size;\n
            this.backBufferTile.imageSize = this.layer.getImageSize(this.bounds) || this.size;\n
            this.backBufferTile.imageOffset = this.layer.imageOffset;\n
            this.backBufferTile.resolution = this.layer.getResolution();\n
        } \n
    },\n
    \n
    /**\n
     * Method: hideBackBuffer\n
     */\n
    hideBackBuffer: function() {\n
        if (this.backBufferTile) {\n
            this.backBufferTile.clear();\n
        }    \n
    },\n
    \n
    /**\n
     * Method: showBackBufferTile\n
     * Displays the backbuffer tile. Renders the image of \n
     * the last request on the backbuffer canvas, scales the \n
     * image to the currrent zoom-level and displays at the canvas \n
     * at its new position.\n
     */\n
    showBackBufferTile: function() {\n
        // backBufferTile has to be valid and ready to use\n
        if (!this.backBufferTile || !this.backBufferTile.lastImage || \n
                (this.backBufferTile.lastImage.src === \'\')) {\n
            return;\n
        }\n
        \n
        if (!this.backBufferTile.canvas) {\n
            this.backBufferTile.initCanvas();\n
        }\n
\n
        // calculate the ratio of change between the current resolution of the\n
        // backBufferTile and the layer.  If several animations happen in a\n
        // row, then the backBufferTile will scale itself appropriately for\n
        // each request.\n
        var ratio = 1;\n
        if (this.backBufferTile.resolution) {\n
            ratio = this.backBufferTile.resolution / this.layer.getResolution();\n
        }\n
        \n
        // if the resolution is not the same as it was last time (i.e. we are\n
        // zooming), then we need to adjust the backBuffer tile\n
        if (this.backBufferTile.resolution &&\n
                (this.backBufferTile.resolution !== this.layer.getResolution())) {\n
            if (this.layer.transitionEffect == \'resize\') {\n
                var mapExtent = this.layer.map.getExtent()\n
                var withinMapExtent = (mapExtent && this.backBufferTile.bounds.intersectsBounds(mapExtent, false));\n
                \n
                if (withinMapExtent) {\n
                    // In this case, we can just immediately resize the \n
                    // backBufferTile.\n
                    var size = new OpenLayers.Size(this.backBufferTile.size.w * ratio, this.backBufferTile.size.h * ratio);\n
                    \n
                    this.backBufferTile.setFramePosition(size);\n
                    \n
                    var imageSize = this.backBufferTile.imageSize;\n
                    imageSize = new OpenLayers.Size(imageSize.w * ratio, imageSize.h * ratio);\n
                    var imageOffset = this.backBufferTile.imageOffset;\n
                    if (imageOffset) {\n
                        imageOffset = new OpenLayers.Pixel(imageOffset.x * ratio, imageOffset.y * ratio);\n
                    }\n
                    \n
                    if (!this.isTooBigCanvas(imageSize)) {\n
                        // set canvas size\n
                        this.backBufferTile.setCanvasSize(imageSize, imageOffset);\n
                        \n
                        var ctx = this.backBufferTile.canvasContext;\n
                        if (ctx.mozImageSmoothingEnabled) {\n
                            /* For Firefox images will be smoothed when they are drawn scaled. Smoothing \n
                             * creates a semi-transparent border, which looks like a white line. Since\n
                             * Firefox 3.6 smoothing can be turned off.\n
                             */\n
                            ctx.mozImageSmoothingEnabled = false;\n
                        }\n
                        this.backBufferTile.drawImage(this.backBufferTile.lastImage, imageSize, true);\n
                    }\n
                }\n
            }\n
        } else {\n
            // otherwise, if the resolution has not changed (when panning), display\n
            // the backbuffer tile at the new position\n
            if (this.layer.singleTile) {\n
                this.backBufferTile.setFramePosition(this.size);\n
                this.backBufferTile.setCanvasSize(this.size, null);\n
                this.backBufferTile.drawImage(this.backBufferTile.lastImage, this.size, true);\n
            } else {\n
                this.backBufferTile.clear();\n
            }\n
        }   \n
    },\n
    \n
    /**\n
     * Method: setFramePosition\n
     * Sets the frame\'s position and size.\n
     * \n
     * Parameters:\n
     * size - {<OpenLayers.Size>} The target size of the frame\n
     */\n
    setFramePosition: function(size) {\n
        var upperLeft = new OpenLayers.LonLat(this.bounds.left, this.bounds.top);\n
        var px = this.layer.map.getLayerPxFromLonLat(upperLeft);\n
        OpenLayers.Util.modifyDOMElement(this.frame, null, px, size);\n
    },\n
    \n
    /**\n
     * Method: setCanvasSize\n
     * Sets the canvas\' size.\n
     * \n
     * Parameters:\n
     * size - {<OpenLayers.Size>} The target size of the canvas element\n
     * imageOffset - {<OpenLayers.Pixel>} Offset\n
     */\n
    setCanvasSize: function(size, imageOffset) {\n
        OpenLayers.Util.modifyDOMElement(this.canvas, null, imageOffset, size);\n
        this.canvas.width = size.w;\n
        this.canvas.height = size.h;\n
    },\n
    \n
    /** \n
     * Method: isTooBigCanvas\n
     * Used to avoid that the backbuffer canvas gets too big when zooming in very fast.\n
     * Otherwise drawing the canvas would take too long and lots of memory would be\n
     * required. \n
     */\n
    isTooBigCanvas: function(size) {\n
        return size.w > 5000;    \n
    },\n
\n
    /**\n
     * Method: getPixelData\n
     * Returns the ARGB values of the pixel at the given position. The\n
     * returned object has the attributes \'a\', \'r\', \'g\' and \'b\'.\n
     * \n
     * Parameters:\n
     * x - {int} x coordinate on the canvas \n
     * y - {int} y coordinate on the canvas\n
     * \n
     * Returns:\n
     * {Object}\n
     */\n
    getPixelData: function(x, y) {\n
        if (this.cancas === null || \n
            x >= this.canvas.width || y >= this.canvas.height) {\n
            return null;\n
        }\n
        if (this.canvasContext !== null) {\n
            if (this.canvasImageData === null) {\n
                this.canvasImageData = this.canvasContext.getImageData(0, 0, \n
                                            this.canvas.width, this.canvas.height);\n
            }\n
            return OpenLayers.Tile.CanvasImage.getPixelDataFromImageData(this.canvasImageData, x, y);\n
        }\n
        return null;\n
    },\n
\n
    /**\n
     * Method: filter\n
     * Applies a canvas filter to the image. If \'layer.canvasAsync\'\n
     * is set, the filter is applied in a web worker.\n
     * \n
     * Parameters:\n
     * image - {Image}\n
     */    \n
    filter: function(image) {\n
        if (!this.layer.canvasAsync || !this.layer.canvasFilter.supportsAsync()) {\n
            // don\'t use a web worker, apply the filter in the main script\n
            var filteredImage = this.layer.canvasFilter.process(image);\n
            // mark the image as filtered\n
            filteredImage.filtered = true;\n
            this.displayImage(filteredImage);\n
        } else {\n
            // apply the filter in a web worker\n
            // called when the filter was applied\n
            var handlerDone = function(resultCanvas) {\n
                if (this.tile.lastImage === this.image) {\n
                    resultCanvas.filtered = true;\n
                    this.tile.displayImage(resultCanvas);   \n
                }\n
            };    \n
            // called when the web worker reports its progress\n
            var handlerProgress = function(progress) {\n
                if (this.tile.lastImage !== this.image) {\n
                    // only report progress, if the tile is not used\n
                    // for requesting a new image\n
                    return;\n
                }\n
                var event = {\n
                    progress: progress,\n
                    tile: this.tile\n
                };\n
                this.tile.events.triggerEvent("filterProgress", event);\n
            };\n
            \n
            // called in case of an error\n
            var handlerError = function(error) {\n
                this.error = error;\n
                this.tile.onErrorFunction(this);\n
            };\n
            \n
            var context = {\n
                tile: this,\n
                // use lastImage instead of image,\n
                // because image may have been reprojected\n
                image: this.lastImage    \n
            };\n
           \n
            // start the web worker\n
            this.layer.canvasFilter.processAsync(\n
                image,\n
                OpenLayers.Function.bind(handlerDone, context),\n
                OpenLayers.Function.bind(handlerProgress, context),\n
                OpenLayers.Function.bind(handlerError, context)\n
            );\n
        }   \n
    },\n
    \n
    /**\n
     * Method: reproject\n
     * Calls gdalwarp-js to reproject the image.\n
     * \n
     * Parameters:\n
     * image - {Image}\n
     * sourceCRS - {<OpenLayers.Projection>}\n
     * sourceBounds - {<OpenLayers.Bounds>} \n
     * sourceSize - {<OpenLayers.Size>} \n
     * targetCRS - {<OpenLayers.Projection>} \n
     * targetBounds - {<OpenLayers.Bounds>} \n
     * targetSize - {<OpenLayers.Size>} \n
     * \n
     * Returns:\n
     * {Canvas}\n
     */\n
    reproject: function(image, sourceCRS, sourceBounds, sourceSize, \n
                                    targetCRS, targetBounds, targetSize) {\n
        \n
        var warper = new GDALWarp(image, sourceCRS.proj, sourceBounds, sourceSize, \n
                                            targetCRS.proj, targetBounds, targetSize);\n
        \n
        if (!this.layer.canvasAsync) {\n
            this.displayImage(warper.reproject());\n
        } else {\n
            var handlerDone = function(resultCanvas) {\n
                if (this.tile.lastImage === this.image) {\n
                    this.tile.displayImage(resultCanvas);   \n
                }\n
            };    \n
            \n
            var handlerProgress = function(progress) {\n
                if (this.tile.lastImage !== this.image) {\n
                    // only report progress, if the tile has not\n
                    // requested a new image\n
                    return;\n
                }\n
                \n
                var event = {\n
                    progress: progress,\n
                    tile: this.tile\n
                };\n
                this.tile.events.triggerEvent("reprojectionProgress", event);\n
            };\n
            \n
            var handlerError = function(error) {\n
                this.error = error;\n
                this.tile.onErrorFunction(this);\n
            };\n
            \n
            var context = {\n
                tile: this,\n
                image: image    \n
            };\n
            \n
            if (this.layer.proj4JSPath === null || \n
                this.layer.gdalwarpWebWorkerPath === null) {\n
                OpenLayers.Console.warn("Trying to reproject layer \'" + this.layer.name + "\' but" + \n
                    "either the path to Proj4JS or to the gdalwarp-js web worker script is not set!"); \n
                return;       \n
            }\n
            \n
            warper.reprojectAsync(\n
                this.layer.proj4JSPath,\n
                OpenLayers.Function.bind(handlerDone, context),\n
                OpenLayers.Function.bind(handlerProgress, context),\n
                OpenLayers.Function.bind(handlerError, context),\n
                this.layer.proj4JSDefinitions,\n
                this.layer.gdalwarpWebWorkerPath);\n
        }          \n
    },\n
    \n
    CLASS_NAME: "OpenLayers.Tile.CanvasImage"\n
  }\n
);\n
\n
/**\n
 * Method: getPixelDataFromImageData\n
 * Returns the ARGB values of the pixel at the given position. The\n
 * returned object has the attributes \'a\', \'r\', \'g\' and \'b\'.\n
 * \n
 * Parameters:\n
 * imageData - {ImageData} the ImageData object\n
 * x - {int} x coordinate on the canvas \n
 * y - {int} y coordinate on the canvas\n
 * \n
 * Returns:\n
 * {Object}\n
 */\n
OpenLayers.Tile.CanvasImage.getPixelDataFromImageData = function(imageData, x, y) {\n
    return {\n
        r: OpenLayers.Tile.CanvasImage.getPixelValue(imageData, x, y, 0),\n
        g: OpenLayers.Tile.CanvasImage.getPixelValue(imageData, x, y, 1),\n
        b: OpenLayers.Tile.CanvasImage.getPixelValue(imageData, x, y, 2),\n
        a: OpenLayers.Tile.CanvasImage.getPixelValue(imageData, x, y, 3)\n
    };    \n
};\n
    \n
/**\n
 * Method: getPixelValue\n
 * Returns the red, green, blue or alpha value\n
 * for the pixel at the given position.\n
 * \n
 * Parameters:\n
 * imageData - {ImageData} the ImageData object\n
 * x - {int} x coordinate on the canvas \n
 * y - {int} y coordinate on the canvas\n
 * argb - 0-3 (0: Red, 1: Green, 2: Blue, 3: Alpha)\n
 * \n
 * Returns:\n
 * {int} 0-255\n
 */\n
OpenLayers.Tile.CanvasImage.getPixelValue = function(imageData, x, y, argb) {\n
    return imageData.data[((y*(imageData.width*4)) + (x*4)) + argb];    \n
};\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>35775</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>CanvasImage.js</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
