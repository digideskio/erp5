<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="PythonScript" module="Products.PythonScripts.PythonScript"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>Script_magic</string> </key>
            <value> <int>3</int> </value>
        </item>
        <item>
            <key> <string>_bind_names</string> </key>
            <value>
              <object>
                <klass>
                  <global name="NameAssignments" module="Shared.DC.Scripts.Bindings"/>
                </klass>
                <tuple/>
                <state>
                  <dictionary>
                    <item>
                        <key> <string>_asgns</string> </key>
                        <value>
                          <dictionary>
                            <item>
                                <key> <string>name_container</string> </key>
                                <value> <string>container</string> </value>
                            </item>
                            <item>
                                <key> <string>name_context</string> </key>
                                <value> <string>context</string> </value>
                            </item>
                            <item>
                                <key> <string>name_m_self</string> </key>
                                <value> <string>script</string> </value>
                            </item>
                            <item>
                                <key> <string>name_subpath</string> </key>
                                <value> <string>traverse_subpath</string> </value>
                            </item>
                          </dictionary>
                        </value>
                    </item>
                  </dictionary>
                </state>
              </object>
            </value>
        </item>
        <item>
            <key> <string>_body</string> </key>
            <value> <string encoding="cdata"><![CDATA[

from Products.PythonScripts.standard import html_quote\n
from Products.CMFCore.utils import getToolByName\n
from Products.FCKeditor.utils import fckCreateValidZopeId\n
\n
\n
# Author : Youenn Broussard - alias youyou (!) on macadames.com ;-)\n
# modified by Jean-mat 05/03/06 for new xml attributes compliance and charset questions\n
\n
\n
# 1. Config\n
\n
# Path to user files relative to the document root.\n
ConfigUserFilesPath=""\n
# SECURITY TIP: Uncomment the following line to set a fixed path\n
# ConfigUserFilesPath = "/UserFiles/"\n
# SECURITY TIP: Uncomment the 3 following code lines to force the Plone Member Home Folder as fixed path\n
# You can do it as well with wysiwyg_support templates customization\n
# it\'s just more secure  \n
# portal=context.portal_url.getPortalObject()\n
# portal_url=portal.absolute_url()\n
# ConfigUserFilesPath = portal.portal_membership.getHomeUrl().replace(portal_url, \'\') + \'/\'\n
\n
# special review_states \n
# (unpublished states for contents which need to be hidden to local_roles\n
# not in rolesSeeUnpublishedContent even with View permission )\n
unpublishedStates=[\'visible\',\'pending\',\'rejected\', \'waitreview\']\n
\n
# special local_roles who can see unpublished contents according to permissions\n
# by default set to None \n
rolesSeeUnpublishedContent = None\n
# you can force the value here\n
# rolesSeeUnpublishedContent = [\'Manager\',\'Reviewer\',\'Owner\', \'Contributor\']\n
\n
# if rolesSeeUnpublishedContent is None we try to take it from portal_properties > navtree_properties \n
if not rolesSeeUnpublishedContent:\n
  try:\n
    props=getToolByName(context,\'portal_properties\')\n
    if hasattr(props,\'navtree_properties\'):\n
        props=props.navtree_properties\n
    rolesSeeUnpublishedContent=getattr(props,\'rolesSeeUnpublishedContent\',  [\'Manager\',\'Reviewer\',\'Owner\'])\n
  except:\n
    rolesSeeUnpublishedContent = [\'Manager\',\'Reviewer\',\'Owner\']\n
\n
# Allowed and denied extensions dictionaries\n
\n
ConfigAllowedExtensions = {"File":None,\n
                           "Image":("jpg","gif","jpeg","png"),\n
                           "Flash":("swf","fla"),\n
                           "Media":("swf",\n
                                    "fla",\n
                                    "jpg",\n
                                    "gif",\n
                                    "jpeg",\n
                                    "png",\n
                                    "avi",\n
                                    "mpg",\n
                                    "mpeg",\n
                                    "mp1",\n
                                    "mp2",\n
                                    "mp3",\n
                                    "mp4",\n
                                    "wma",\n
                                    "wmv",\n
                                    "wav",\n
                                    "mid",\n
                                    "midi",\n
                                    "rmi",\n
                                    "rm",\n
                                    "ram",\n
                                    "rmvb",\n
                                    "mov",\n
                                    "qt")}\n
ConfigDeniedExtensions =  {"File":("py",\n
                                   "cpy",\n
                                   "pt",\n
                                   "cpt",\n
                                   "dtml",\n
                                   "php",\n
                                   "asp",\n
                                   "aspx",\n
                                   "ascx",\n
                                   "jsp",\n
                                   "cfm",\n
                                   "cfc",\n
                                   "pl",\n
                                   "bat",\n
                                   "exe",\n
                                   "com",\n
                                   "dll",\n
                                   "vbs",\n
                                   "js",\n
                                   "reg"),\n
                          "Image":None,\n
                          "Flash":None,\n
                          "Media":None}\n
\n
# set link by UID for AT content Types \n
# change value to 0 to disable it \n
linkbyuid=1\n
\n
CPS_FOLDER_TYPE=[\'Workspace\',\'ImageGallery\',\'CPS Proxy Folder\',\'CPS Proxy Folderish Document\']\n
\n
# find Plone Site charset (todo : CPS compliance (how ?))\n
\n
try:\n
  prop   = getToolByName(context, "portal_properties")\n
  charsetSite = prop.site_properties.getProperty("default_charset", "utf-8")\n
except:\n
  charsetSite ="iso-8859-1"\n
\n
# 2. utils\n
\n
def RemoveFromStart(sourceString,charToRemove ):\n
  return sourceString.lstrip(charToRemove)\n
\n
def utf8Encode(chaine) :\n
\n
    errors="strict"\n
    if charsetSite.lower() in ("utf-8", "utf8"):\n
      return chaine\n
    else:\n
      return unicode(chaine, charsetSite, errors).encode("utf-8", errors)\n
\n
def utf8Decode(chaine) :\n
    # because browser upload form is in utf-8 we need it\n
    errors="strict"\n
    if charsetSite.lower() in ("utf-8", "utf8"):\n
        return chaine\n
    else:\n
        try:\n
            chaine = unicode(chaine, "utf-8", "strict").encode(charsetSite, "strict")\n
        except:\n
            chaine = chaine.encode(charsetSite, "strict")\n
        return chaine\n
\n
def ConvertToXmlAttribute( value ):\n
  return utf8Encode(value).replace("\\"", "&quot;").replace("&", "&amp;")\n
\n
\n
\n
\n
# 3. io\n
\n
\n
\n
def GetUrlFromPath( folderPath ) :\n
\n
    return \'%s%s\' %(portal_path,folderPath.rstrip("/"))\n
\n
\n
def RemoveExtension( fileName ):\n
\n
   sprout=fileName.split(".")\n
   return \'.\'.join(sprout[:len(sprout)-1])\n
\n
def  IsAllowedExt( extension, resourceType ) :\n
  \n
   sAllowed = ConfigAllowedExtensions[resourceType]\n
   sDenied = ConfigDeniedExtensions[resourceType]\n
\n
   if (sAllowed is None or extension in sAllowed) and (sDenied is None or extension not in sDenied) :\n
     return 1\n
   else :\n
     return 0\n
\n
def FindExtension (fileName):\n
\n
   sprout=fileName.split(RemoveExtension(fileName))\n
   return \'\'.join(sprout).lstrip(\'.\')\n
\n
  \n
\n
\n
\n
# 4. basexml\n
\n
def CreateXmlHeader( command, resourceType, currentFolder ):\n
    header = [\'<?xml version="1.0" encoding="utf-8" ?>\']\n
    header.append(\'\\r<Connector command="%s" resourceType=" %s ">\'% (command,resourceType))\n
    header.append(\'\\r    <CurrentFolder path="%s" url="%s/" />\'% (ConvertToXmlAttribute(currentFolder),ConvertToXmlAttribute(GetUrlFromPath(currentFolder))))\n
    return \'\'.join(header)\n
\n
\n
def CreateXmlFooter():\n
    return \'\\r</Connector>\'\n
\n
\n
\n
def xmlString(results, resourceType, foldersOnly):\n
\n
    # traitement xml\n
    xmlFiles=[\'\\r        <Files>\']\n
    xmlFolders=[\'\\r        <Folders>\']\n
    \n
    for result in results :\n
        \n
        titre = result.title_or_id()\n
        if linkbyuid and hasattr(result, \'UID\'):\n
           tagLinkbyuid="yes"\n
           uid = result.UID()\n
        else :\n
           tagLinkbyuid="no"\n
           uid=""\n
        \n
        if result.meta_type in CPS_FOLDER_TYPE :\n
            \n
            try:\n
               xmlFolders.append(\'\\r            <Folder name="%s" title="%s" linkbyuid="%s" uid="%s" type="%s" metatype="%s" />\'%(ConvertToXmlAttribute(result.id),ConvertToXmlAttribute(titre), tagLinkbyuid, uid, resourceType, ConvertToXmlAttribute(result.meta_type)))\n
               \n
            except Exception , e:\n
               pass\n
            \n
        else :\n
            tagPhoto= "no"\n
            \n
            size=0\n
            try:\n
               size= result.getContent().get_size()\n
            except Exception,e:\n
               \n
               pass\n
            try:\n
               xmlFiles.append(\'\\r            <File name="%s/preview" size="%s" title="%s" photo="%s" linkbyuid="%s" uid="%s" type="%s" isPA3img="no" isattach="no" attachid="" />\'%(ConvertToXmlAttribute(result.getId()),size,ConvertToXmlAttribute(titre), tagPhoto, tagLinkbyuid, uid, resourceType))\n
               \n
            except Exception,e:\n
               pass\n
   \n
    xmlFiles.append(\'\\r        </Files>\')\n
    xmlFolders.append(\'\\r        </Folders>\')\n
    \n
    if foldersOnly:\n
        stringXml=\'\'.join(xmlFolders)\n
    else :\n
        stringXml=\'\'.join(xmlFolders)+\'\'.join(xmlFiles)\n
    return stringXml\n
\n
\n
def CreateXmlErrorNode (errorNumber,errorDescription):\n
\n
    return \'\\r        <Error number="\' + errorNumber + \'" originalNumber="\' + errorNumber + \'" originalDescription="\' + ConvertToXmlAttribute( errorDescription ) + \'" />\'\n
\n
\n
# 5. commands\n
# Specific CPS , for special folderish (doc flexible ...) change these lines\n
\n
def GetFoldersAndFiles( resourceType, currentFolder ):\n
    results=[]\n
    user=context.REQUEST[\'AUTHENTICATED_USER\']\n
    types=context.portal_types\n
    all_portal_types = [ctype.content_meta_type for ctype in types.objectValues()]\n
    \n
    accepted_values=[\'CPS Proxy Document\',]\n
    if resourceType=="Image" :\n
      accepted_types=[ctype.id for ctype in types.objectValues() if ctype.id in (\'Image\', )]\n
      \n
    elif resourceType=="Flash":\n
      accepted_types=[ctype.id for ctype in types.objectValues() if ctype.id in (\'Flash Animation\', )]\n
      \n
    #elif resourceType not in (\'Image\', \'Flash\') :\n
    #  accepted_types=[ctype.id for ctype in types.objectValues()]\n
      \n
    else :\n
      accepted_types = [ctype.id for ctype in types.objectValues()]\n
    if currentFolder != "/" :\n
      try:\n
        obj = context.restrictedTraverse(currentFolder.lstrip(\'/\'))\n
      except Exception,e:\n
        \n
        obj = context.portal_url.getPortalObject()\n
    else :\n
      \n
      obj = context.portal_url.getPortalObject()\n
        \n
    \n
    for object in obj.objectValues( accepted_values + CPS_FOLDER_TYPE):\n
      mtool = context.portal_membership\n
      checkPerm = mtool.checkPermission\n
\n
      if not checkPerm(\'View\', object):\n
        pass\n
      \n
      \n
      if object.portal_type in accepted_types or (object.meta_type in CPS_FOLDER_TYPE) :\n
         \n
        results.append(object)\n
    results = [ s for s in results if user.has_permission(\'View\', s) ]\n
    \n
    return xmlString(results,resourceType,0)\n
\n
\n
def GetFolders( resourceType, currentFolder ):\n
    results=[]\n
    user=context.REQUEST[\'AUTHENTICATED_USER\']\n
    types=context.portal_types\n
    \n
     \n
    all_portal_types = [ctype.content_meta_type for ctype in types.objectValues()]\n
    if currentFolder != "/" :\n
        \n
        #try:\n
           \n
        obj = context.restrictedTraverse(currentFolder.lstrip(\'/\'))\n
        #except Exception,e:\n
           \n
        #   obj = context.portal_url.getPortalObject()\n
            \n
    else :\n
        #obj = context.portal_url.getPortalObject()\n
        return xmlString([],resourceType,1)\n
        #\n
    \n
    #if obj.meta_type == \'CPSDefault Site\':\n
    #    obj=obj.sections\n
    \n
\n
    mtool = context.portal_membership\n
    checkPerm = mtool.checkPermission \n
    \n
    for object in obj.objectValues(CPS_FOLDER_TYPE):\n
      \n
      \n
      # filter out objects that cannot be viewed\n
      if not user.has_permission(\'View\', object):\n
        \n
        continue\n
      \n
        \n
      try:\n
        if object.meta_type in CPS_FOLDER_TYPE and object.meta_type in all_portal_types  :\n
          \n
          #review_state=container.portal_workflow.getInfoFor(object, \'review_state\', \'\')\n
          start_pub=getattr(object,\'effective_date\',None)\n
          end_pub=getattr(object,\'expiration_date\',None)\n
          if not ((start_pub and start_pub > DateTime()) or (end_pub and DateTime() > end_pub)):\n
            results.append(object)\n
          elif user.has_role(rolesSeeUnpublishedContent,object) :\n
            results.append(object)\n
      except Exception,e:\n
          pass  \n
    results = [ s for s in results if user.has_permission(\'View\', s) ]\n
     \n
    return xmlString(results,resourceType,1)\n
\n
\n
def CreateFolder(currentFolder, folderName ):\n
\n
    user=context.REQUEST[\'AUTHENTICATED_USER\']\n
    if currentFolder != "/" :\n
        obj = context.restrictedTraverse(currentFolder.lstrip(\'/\'))\n
    else :\n
        obj = context.portal_url.getPortalObject()\n
    sErrorNumber=""\n
\n
    # error cases\n
    if not user.has_permission(\'Add portal content\', obj) and not user.has_permission(\'Modify portal content\', obj):\n
       sErrorNumber = "103"\n
       sErrorDescription = "folder creation forbidden"\n
\n
    if not folderName:\n
       sErrorNumber = "102"\n
       sErrorDescription = "invalid folder name"\n
\n
    if not sErrorNumber :\n
      try :\n
        folderTitle=utf8Decode(folderName)\n
        folderName = fckCreateValidZopeId(utf8Encode(folderName))\n
        new_id = obj.invokeFactory(id=folderName, type_name=\'Folder\', title=folderTitle)\n
        sErrorNumber = "0"\n
        sErrorDescription = "success"\n
      except :\n
        sErrorNumber = "103"\n
        sErrorDescription = "folder creation forbidden"\n
\n
    return CreateXmlErrorNode(sErrorNumber,sErrorDescription)\n
       \n
\n
\n
\n
# 6. upload\n
\n
def UploadFile(resourceType, currentFolder, data, title) :\n
\n
        user=context.REQUEST[\'AUTHENTICATED_USER\']\n
        if currentFolder != "/" :\n
            obj = context.restrictedTraverse(currentFolder.lstrip(\'/\'))\n
        else :\n
            obj = context.portal_url.getPortalObject()\n
        error=""\n
        idObj=""\n
         \n
        # define Portal Type to add\n
\n
\n
        if resourceType == \'Flash\':\n
            typeToAdd=\'Flash Animation\'\n
        elif resourceType in (\'File\', \'Flash\', \'Media\'):\n
            typeToAdd = \'File\'\n
        elif resourceType == \'Image\' :\n
            typeToAdd=\'Image\'\n
         \n
        \n
\n
        if not user.has_permission(\'Add portal content\', obj) and not user.has_permission(\'Modify portal content\', obj):\n
           error = "103"\n
\n
        if not data:\n
          #pas de fichier \n
          error= "202"\n
\n
\n
        titre_data=\'\'\n
        filename=utf8Decode(getattr(data,\'filename\', \'\'))\n
        titre_data=filename[max(string.rfind(filename, \'/\'),\n
                        string.rfind(filename, \'\\\\\'),\n
                        string.rfind(filename, \':\'),\n
                        )+1:]                  \n
\n
        idObj=fckCreateValidZopeId(utf8Encode(titre_data))\n
\n
        if title :\n
           titre_data=title\n
\n
        if not IsAllowedExt( FindExtension(idObj), resourceType ):\n
              error= "202"\n
         \n
        if not error :              \n
            error="0"\n
            indice=0\n
            exemple_titre=idObj\n
            while exemple_titre in obj.objectIds():\n
              indice=indice+1\n
              exemple_titre=str(indice) + idObj\n
            if indice!=0:\n
                error= "201"\n
                idObj = exemple_titre\n
\n
            try:\n
                # this method need to be changed for browser refresh\n
                # because it send 302 redirection : we need no http response\n
                request=context.REQUEST\n
                request.form.update({\'widget__preview\':data,\'widget__preview_choice\':\'change\',\'type_name\':typeToAdd,\'widget__Title\':titre_data, \'cpsdocument_create_button\':1,\'widget__LanguageSelectorCreation\':\'fr\'})\n
                ti=context.portal_types[typeToAdd]\n
                res = ti.renderCreateObjectDetailed(container=obj, request=request,\n
                                    validate=1, layout_mode=\'create\',\n
                                    create_callback=\'createCPSDocument_cb\',\n
                                    created_callback=\'cpsdocument_created\')\n
                \n
                #context.createCPSDocument(context=obj,REQUEST=request)\n
                obj.reindexObject()\n
                \n
            except Exception , e :\n
                \n
                error = "103"\n
                \n
        \n
        d= \'\'\'\n
        <script type="text/javascript">\n
        window.parent.frames[\'frmUpload\'].OnUploadCompleted(%s,%s) ;\n
        </script>\n
        \'\'\'% (error,idObj)\n
        \n
        return d\n
\n
\n
#7. connector \n
\n
\n
request = context.REQUEST\n
RESPONSE =  request.RESPONSE\n
dicoRequest = request.form\n
message_error=""\n
\n
portal_url=context.portal_url.getPortalObject().absolute_url()\n
server_url = request.SERVER_URL\n
portal_path = portal_url.replace(server_url,\'\')\n
\n
if ConfigUserFilesPath != "" :\n
   sUserFilesPath = ConfigUserFilesPath\n
elif dicoRequest.has_key(\'ServerPath\'):\n
   sUserFilesPath = dicoRequest [\'ServerPath\']\n
else :\n
   sUserFilesPath = "/"\n
\n
\n
if dicoRequest.has_key(\'CurrentFolder\'):\n
   sCurrentFolder = dicoRequest [\'CurrentFolder\']\n
   if sUserFilesPath!=\'/\' and sUserFilesPath.rstrip(\'/\') not in sCurrentFolder:\n
        sCurrentFolder = sUserFilesPath\n
else :\n
   message_error="No CurrentFolder in request"\n
\n
\n
\n
if dicoRequest.has_key(\'Command\'):\n
    sCommand = dicoRequest [\'Command\']\n
else :\n
    message_error="No Command in request"\n
\n
if dicoRequest.has_key(\'Type\'):\n
    sResourceType = dicoRequest [\'Type\']\n
else :\n
    message_error="No Type in request"\n
\n
\n
if dicoRequest.has_key(\'NewFolderName\'):\n
    sFolderName = dicoRequest [\'NewFolderName\']\n
\n
\n
# interception File Upload\n
if sCommand==\'FileUpload\' and dicoRequest.has_key(\'NewFile\'):\n
    sData = dicoRequest [\'NewFile\']\n
    sTitle = utf8Decode(dicoRequest [\'Title\'])\n
    chaineHtmlUpload = UploadFile(sResourceType, sCurrentFolder, sData, sTitle)\n
    RESPONSE.setHeader(\'Content-type\', \'text/html; charset=%s\' % charsetSite)\n
    return chaineHtmlUpload\n
\n
\n
else :\n
\n
    # Creation response XML\n
    if not message_error :\n
\n
        RESPONSE.setHeader(\'Cache-control\', \'pre-check=0,post-check=0,must-revalidate,s-maxage=0,max-age=0,no-cache\')\n
        RESPONSE.setHeader(\'Content-type\', \'text/xml; charset=utf-8\')\n
        \n
        xmlHeader = CreateXmlHeader (sCommand, sResourceType, sCurrentFolder)\n
        \n
        if sCommand=="GetFolders":\n
            xmlBody = GetFolders (sResourceType, sCurrentFolder)\n
        elif sCommand=="GetFoldersAndFiles":\n
            xmlBody = GetFoldersAndFiles (sResourceType, sCurrentFolder)\n
        elif sCommand=="CreateFolder":\n
            xmlBody = CreateFolder (sCurrentFolder,sFolderName)\n
\n
        xmlFooter = CreateXmlFooter()\n
        return xmlHeader + xmlBody + xmlFooter\n
\n
    # creation response error request\n
    else :\n
        \n
        sErrorNumber="218"\n
        sErrorDescription="Browser Request exception : " + message_error\n
        xmlHeader = CreateXmlHeader (sCommand, sResourceType, sCurrentFolder)\n
        xmlFooter = CreateXmlFooter()\n
        return xmlHeader + CreateXmlErrorNode(sErrorNumber,sErrorDescription) + xmlFooter\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>Command=\'\',Type=\'\',CurrentFolder=\'\',NewFolderName=\'\'</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>connectorCPS.py</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
