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
\n
# Author : jean-mat Grimaldi - jean-mat@macadames.com\n
# Thanks to Martin F. Krafft (alias madduck on sourceforge) for some corrections\n
# Thanks to kupu developpers for UID referencing\n
# This connector is plone specific\n
# Some functions need to be adapted for other Zope CMS compatibility\n
\n
# 1. Config\n
\n
# Path to user files relative to the document root.\n
# security tip\n
ConfigUserFilesPath=""\n
\n
# dico fck parameters for browsing\n
fckParams=context.getFck_params()\n
\n
\n
# special review_states \n
# (unpublished states for contents which need to be hidden to local_roles\n
# not in fck prefs rolesSeeUnpublishedContent even with View permission )\n
unpublishedStates=fckParams[\'fck_unpublished_states\']\n
\n
# special local_roles who can see unpublished contents according to permissions\n
# by default set to fck unpublished view roles (fck prefs) \n
rolesSeeUnpublishedContent = fckParams[\'fck_unpublished_view_roles\']\n
\n
# PloneArticle based meta_types\n
pa_meta_types = fckParams[\'pa_meta_types\']\n
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
linkbyuid=test(fckParams[\'allow_link_byuid\'],1,0)\n
\n
# check if upload allowed for Links Image and internal links\n
\n
allow_file_upload=test(fckParams[\'allow_server_browsing\'],test(fckParams[\'allow_file_upload\'],1,0),0)\n
allow_image_upload=test(fckParams[\'allow_server_browsing\'],test(fckParams[\'allow_image_upload\'],1,0),0)\n
allow_flash_upload=test(fckParams[\'allow_server_browsing\'],test(fckParams[\'allow_flash_upload\'],1,0),0)\n
\n
\n
# check for portal_types when uploading internal links, images and files\n
\n
file_portal_type = test(fckParams[\'file_portal_type\'],fckParams[\'file_portal_type\'],\'File\')\n
image_portal_type = test(fckParams[\'image_portal_type\'],fckParams[\'image_portal_type\'],\'Image\')\n
flash_portal_type = test(fckParams[\'flash_portal_type\'],fckParams[\'flash_portal_type\'],\'File\')\n
\n
# find Plone Site charset \n
\n
try:\n
  prop   = getToolByName(context, "portal_properties")\n
  charsetSite = prop.site_properties.getProperty("default_charset", "utf-8")\n
except:\n
  charsetSite ="utf-8"\n
\n
\n
# 2. utils\n
\n
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
\n
def ConvertToXmlAttribute( value ):\n
  return utf8Encode(value).replace("\\"", "&quot;").replace("\'","&rsquo;").replace("&", "&amp;")\n
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
    header.append(\'\\r    <CurrentFolder path="%s" url="%s/" />\'\\\n
                   % (ConvertToXmlAttribute(currentFolder),\n
                      ConvertToXmlAttribute(GetUrlFromPath(currentFolder))))\n
    return \'\'.join(header)\n
\n
\n
def CreateXmlFooter():\n
    return \'\\r</Connector>\'\n
\n
\n
\n
def xmlString(results, resourceType, foldersOnly, isPA):\n
\n
    user=context.REQUEST[\'AUTHENTICATED_USER\']\n
    # traitement xml\n
    xmlFiles=[\'\\r        <Files>\']\n
    xmlFolders=[\'\\r        <Folders>\']\n
\n
\n
    # traitement folderish standard non PloneArticle\n
    if isPA ==0:\n
        for result in results :\n
            titre = result.title_or_id()\n
            if linkbyuid and hasattr(result.aq_explicit, \'UID\'):               \n
               tagLinkbyuid="yes"\n
               uid = result.UID()\n
            else :\n
               tagLinkbyuid="no"\n
               uid=""\n
            if result.isPrincipiaFolderish or result.meta_type in pa_meta_types :\n
                xmlFolders.append(\'\'\'\n
            <Folder name="%s"\n
                    title="%s"\n
                    linkbyuid="%s"\n
                    uid="%s"\n
                    type="%s"\n
                    metatype="%s" />\'\'\'%(ConvertToXmlAttribute(result.getId()),\n
                                         ConvertToXmlAttribute(titre),\n
                                         tagLinkbyuid, uid,\n
                                         resourceType,\n
                                         ConvertToXmlAttribute(result.meta_type)))\n
            else :\n
                if result.meta_type in (\'CMF ZPhoto\', \'CMF Photo\'):\n
                   tagPhoto="yes"\n
                else:\n
                   tagPhoto= "no"\n
                isAttach = "no"\n
                attachId=""\n
                xmlFiles.append(\'\'\'\n
            <File name="%s"\n
                  size="%s"\n
                  title="%s"\n
                  photo="%s"\n
                  linkbyuid="%s"\n
                  uid="%s"\n
                  type="%s"\n
                  isPA3img="no"\n
                  isattach="%s"\n
                  attachid="%s" />\'\'\'%(ConvertToXmlAttribute(result.getId()),\n
                                       str(context.getObjSize(result)),\n
                                       ConvertToXmlAttribute(titre),\n
                                       tagPhoto,\n
                                       tagLinkbyuid,\n
                                       uid,\n
                                       resourceType,\n
                                       isAttach,\n
                                       attachId))\n
    # PloneArticle specific treatment\n
    elif user.has_permission(\'View\', results) :\n
        # find Plone Article version and brains for PA v3\n
        try :\n
            image_brains =results.getImageBrains()\n
            attachment_brains=results.getAttachmentBrains()\n
            versionPA=3\n
        except:\n
            versionPA=2\n
\n
        # Plone Article v3 treatment\n
        if versionPA==3:\n
            atool = context.portal_article\n
            #  PloneArticle 3.x images and attachements\n
            # images\n
            for image_brain in image_brains :\n
                image = image_brain.getObject()\n
                image_field = image.getField(\'image\')\n
                image_name = atool.getFieldFilename(image, image_field)\n
                image_id = image.getId()\n
                image_title = image.title_or_id()\n
                image_size = context.plonearticle_format_size(image.get_size())\n
                tagPhoto= "no"\n
                isAttach = "no"\n
                if linkbyuid and hasattr(image.aq_explicit, \'UID\'):               \n
                    tagLinkbyuid="yes"\n
                    uid = image.UID()\n
                else:\n
                    tagLinkbyuid="no"\n
                    uid=""\n
                xmlFiles.append(\'\'\'\n
            <File name="%s"\n
                  size="%s"\n
                  title="%s"\n
                  photo="%s"\n
                  linkbyuid="%s"\n
                  uid="%s"\n
                  type="%s"\n
                  isPA3img="yes"\n
                  isattach="%s"\n
                  attachid="%s" />\'\'\'%(ConvertToXmlAttribute(image_id), \n
                                       image_size,\n
                                       ConvertToXmlAttribute(image_title),\n
                                       tagPhoto,\n
                                       tagLinkbyuid,\n
                                       uid,\n
                                       resourceType,\n
                                       isAttach,\n
                                       ConvertToXmlAttribute(image_name)))\n
\n
            # files and other resource types\n
            if resourceType!=\'Image\':\n
                for attach_brain in attachment_brains :\n
                    attach = attach_brain.getObject()\n
                    attach_field = attach.getField(\'file\')\n
                    attach_name = atool.getFieldFilename(attach, attach_field)\n
                    attach_id = attach.getId()\n
                    attach_title = attach.title_or_id()\n
                    attach_size = context.plonearticle_format_size(attach.get_size())\n
                    tagPhoto= "no"\n
                    isAttach = "no"\n
                    if linkbyuid and hasattr(attach.aq_explicit, \'UID\'):               \n
                        tagLinkbyuid="yes"\n
                        uid = attach.UID()\n
                    else:\n
                        tagLinkbyuid="no"\n
                        uid=""\n
                    xmlFiles.append(\'\'\'\n
            <File name="%s"\n
                  size="%s"\n
                  title="%s"\n
                  photo="%s"\n
                  linkbyuid="%s"\n
                  uid="%s"\n
                  type="%s"\n
                  isPA3img="no"\n
                  isattach="%s"\n
                  attachid="%s" />\'\'\'%(ConvertToXmlAttribute(attach_id),\n
                                       attach_size,\n
                                       ConvertToXmlAttribute(attach_title),\n
                                       tagPhoto,\n
                                       tagLinkbyuid,\n
                                       uid,\n
                                       resourceType,\n
                                       isAttach,\n
                                       ConvertToXmlAttribute(attach_name)))\n
\n
                \n
        # PloneArticle v2.x\n
        else:\n
            tagLinkbyuid="no"\n
            uid=""\n
            # images\n
            if len(results.listImages())>0:\n
                images = results.listImages()\n
                index=0\n
                for image in images :\n
                    titre = image.title_or_id()\n
                    # get Id\n
                    imageId=results.getImageId(index)\n
                    index +=1\n
                    # get Size object\n
                    try:\n
                        imageSize=image.getSize()\n
                    except:\n
                        imageSize=context.getObjSize(image)\n
                    tagPhoto= "no"\n
                    isAttach = "no"\n
                    attachId = image.getId()\n
                    xmlFiles.append(\'\'\'\n
            <File name="%s"\n
                  size="%s"\n
                  title="%s"\n
                  photo="%s"\n
                  linkbyuid="%s"\n
                  uid="%s"\n
                  type="%s"\n
                  isPA3img="no"\n
                  isattach="%s"\n
                  attachid="%s" />\'\'\'%(ConvertToXmlAttribute(imageId),\n
                                       imageSize,\n
                                       ConvertToXmlAttribute(titre),\n
                                       tagPhoto,\n
                                       tagLinkbyuid,\n
                                       uid,\n
                                       resourceType,\n
                                       isAttach,\n
                                       ConvertToXmlAttribute(attachId)))            \n
\n
            # files and other ressources types\n
            if len(results.listAttachments())>0 and resourceType!=\'Image\':\n
                attachements = results.listAttachments()\n
                index=0\n
                for attachement in attachements :\n
                    titre = attachement.title_or_id()\n
                    # get Id\n
                    attachementId=results.getAttachmentId(index)\n
                    index +=1\n
                    # get Size object\n
                    try:\n
                        attachementSize=attachement.getSize()\n
                    except:\n
                        attachementSize=context.getObjSize(attachement)\n
                    tagPhoto= "no"\n
                    isAttach = "yes"\n
                    attachId=attachement.getFilename()\n
                    xmlFiles.append(\'\'\'\n
            <File name="%s"\n
                  size="%s"\n
                  title="%s"\n
                  photo="%s"\n
                  linkbyuid="%s"\n
                  uid="%s"\n
                  type="%s"\n
                  isPA3img="no"\n
                  isattach="%s"\n
                  attachid="%s" />\'\'\'%(ConvertToXmlAttribute(attachementId),\n
                                       attachementSize,\n
                                       ConvertToXmlAttribute(titre),\n
                                       tagPhoto,\n
                                       tagLinkbyuid,\n
                                       uid,\n
                                       resourceType,\n
                                       isAttach,\n
                                       ConvertToXmlAttribute(attachId)))            \n
\n
\n
\n
    xmlFiles.append(\'\\r        </Files>\')\n
    xmlFolders.append(\'\\r        </Folders>\')\n
    if foldersOnly:\n
        stringXml=\'\'.join(xmlFolders)\n
    else :\n
        stringXml=\'\'.join(xmlFolders)+\'\'.join(xmlFiles)\n
    return stringXml\n
\n
\n
def CreateXmlErrorNode (errorNumber,errorDescription):\n
\n
    return \'\'\'\n
        <Error number="%s"\n
               originalNumber="%s"\n
               originalDescription="%s" />\'\'\'%(errorNumber,\n
                                               errorNumber,\n
                                               ConvertToXmlAttribute(errorDescription))\n
\n
\n
# 5. commands\n
# Specific Plone - for others CMS (CPS ...), for special folderish (Plone Article, doc flexible ...) change these lines\n
\n
def GetFoldersAndFiles( resourceType, currentFolder ):\n
    results=[]\n
    user=context.REQUEST[\'AUTHENTICATED_USER\']\n
    if currentFolder != "/" :\n
        obj = context.restrictedTraverse(currentFolder.lstrip(\'/\'))\n
    else :\n
        obj = context.portal_url.getPortalObject()\n
    # objet folderish\n
    if obj.meta_type not in pa_meta_types:\n
        types=context.portal_types\n
        all_portal_types = [ctype.content_meta_type for ctype in types.objectValues()]\n
        if resourceType=="Image" :\n
          accepted_types=[ctype.content_meta_type for ctype in types.objectValues() if ctype.id in (image_portal_type, \'Photo\', \'ZPhoto\')]\n
        elif resourceType=="Flash" :\n
          accepted_types=[ctype.content_meta_type for ctype in types.objectValues() if ctype.id == flash_portal_type ]\n
        else :\n
          accepted_types = all_portal_types\n
        for object in obj.objectValues():\n
          if object.meta_type in accepted_types or (object.meta_type in all_portal_types  and (object.isPrincipiaFolderish or object.meta_type in pa_meta_types)) :\n
            review_state=container.portal_workflow.getInfoFor(object, \'review_state\', \'\')\n
            start_pub=getattr(object,\'effective_date\',None)\n
            end_pub=getattr(object,\'expiration_date\',None)\n
            if review_state not in unpublishedStates and not ((start_pub and start_pub > DateTime()) or (end_pub and DateTime() > end_pub)):\n
              results.append(object)\n
            elif user.has_role(rolesSeeUnpublishedContent,object) :\n
              results.append(object)\n
        results = [ s for s in results if user.has_permission(\'View\', s) ]\n
        return xmlString(results,resourceType,0,0)\n
\n
    # objet Plone article find attachements and images\n
    else:\n
        # oblige d\'envoyer l\'objet car trop specifique \n
        return xmlString(obj,resourceType,0,1)\n
\n
\n
\n
def GetFolders( resourceType, currentFolder ):\n
    results=[]\n
    user=context.REQUEST[\'AUTHENTICATED_USER\']\n
    types=context.portal_types\n
    all_portal_types = [ctype.content_meta_type for ctype in types.objectValues()]\n
    if currentFolder != "/" :\n
        obj = context.restrictedTraverse(currentFolder.lstrip(\'/\'))\n
    else :\n
        obj = context.portal_url.getPortalObject()\n
    for object in obj.objectValues():\n
      if object.meta_type in all_portal_types and (object.isPrincipiaFolderish or object.meta_type==\'PloneArticle\') :\n
        review_state=container.portal_workflow.getInfoFor(object, \'review_state\', \'\')\n
        start_pub=getattr(object,\'effective_date\',None)\n
        end_pub=getattr(object,\'expiration_date\',None)\n
        if review_state not in unpublishedStates and not ((start_pub and start_pub > DateTime()) or (end_pub and DateTime() > end_pub)):\n
          results.append(object)\n
        elif user.has_role(rolesSeeUnpublishedContent,object) :\n
          results.append(object)\n
    results = [ s for s in results if user.has_permission(\'View\', s) ]\n
    return xmlString(results,resourceType,1,0)\n
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
    if obj.meta_type == \'PloneArticle\':\n
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
        folderName = fckCreateValidZopeId(utf8Encode(folderTitle))\n
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
        if obj.meta_type != \'PloneArticle\':\n
            # define Portal Type to add\n
\n
            if resourceType == \'File\':\n
                typeToAdd = file_portal_type\n
            elif resourceType == \'Flash\':\n
                typeToAdd = flash_portal_type\n
            elif resourceType == \'Image\' :\n
                if obj.meta_type=="CMF ZPhotoSlides":\n
                    typeToAdd = \'ZPhoto\'\n
                elif obj.meta_type=="Photo Album":\n
                    typeToAdd = \'Photo\'\n
                elif obj.meta_type=="ATPhotoAlbum":\n
                    typeToAdd = \'ATPhoto\'\n
                else:\n
                    typeToAdd = image_portal_type\n
        \n
\n
            if not user.has_permission(\'Add portal content\', obj) and not user.has_permission(\'Modify portal content\', obj):\n
               error = "103"\n
\n
            if resourceType == \'Image\' and not allow_image_upload:\n
               error = "103"\n
\n
            if resourceType == \'Flash\' and not allow_flash_upload:\n
               error = "103"\n
\n
            if resourceType not in (\'Flash\',\'Image\') and not allow_file_upload:\n
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
                    obj.invokeFactory(id=idObj, type_name=typeToAdd, title=titre_data )\n
                    newFile = getattr(obj, idObj)\n
                    newFile.edit(file=data)\n
                    obj.reindexObject()\n
\n
                except:\n
                    error = "103"\n
\n
        #Plone Article treatment\n
        else :\n
            # find Plone Article version\n
            try :\n
                image_brains = obj.getImageBrains()\n
                attachment_brains = obj.getAttachmentBrains()\n
                versionPA=3\n
            except:\n
                versionPA=2\n
\n
            if not data:\n
                #pas de fichier \n
                error= "1"        \n
                customMsg="no file uploaded"\n
            else :\n
                filename=utf8Decode(getattr(data,\'filename\', \'\'))\n
                titre_data=filename[max(string.rfind(filename, \'/\'),\n
                                string.rfind(filename, \'\\\\\'),\n
                                string.rfind(filename, \':\'),\n
                                )+1:]                  \n
\n
                # idObj can\'t be cleaned with PloneArticle attachements\n
                # it\'s a problem but we do the job\n
                idObj=fckCreateValidZopeId(utf8Encode(titre_data))\n
                if title :\n
                    titre_data=title\n
                \n
                if resourceType == \'Image\' :\n
                    # Upload file\n
                    if not user.has_permission(\'Modify portal content\', obj):\n
                        error = "103"\n
                    elif not allow_image_upload:\n
                        error = "103"\n
                    elif not IsAllowedExt( FindExtension(idObj), resourceType ):\n
                        error= "202"        \n
                        customMsg="Invalid file type"\n
                    elif obj.portal_article.checkImageSize(data):\n
                        if versionPA==2 :\n
                            obj.appendImage(titre_data, data, )\n
                        else :\n
                            obj.addImage(title=titre_data, description=\'\', image=data)\n
                        error="0"\n
                        try:\n
                            obj.reindexObject()\n
                        except:\n
                            parent = obj.aq_parent\n
                            parent.reindexObject()\n
\n
                    else:\n
                        error="104"\n
                else:\n
                    # Upload file\n
                    if not user.has_permission(\'Modify portal content\', obj):\n
                        error = "103"\n
                    elif not allow_file_upload:\n
                        error = "103"\n
                    elif not IsAllowedExt( FindExtension(idObj), resourceType ):\n
                        error= "202"        \n
                        customMsg="Invalid file type"\n
                    elif obj.portal_article.checkAttachmentSize(data):\n
                        if versionPA==2 :\n
                            obj.appendAttachment(titre_data, data, )\n
                        else :\n
                            obj.addAttachment(title=titre_data, description=\'\', file=data)\n
                        error="0"\n
                        try:\n
                            obj.reindexObject()\n
                        except:\n
                            parent = obj.aq_parent\n
                            parent.reindexObject()\n
                    else:\n
                        error="104"\n
\n
\n
        d= \'\'\'\n
        <script type="text/javascript">\n
        window.parent.frames[\'frmUpload\'].OnUploadCompleted(%s,"%s") ;\n
        </script>\n
        \'\'\'% (error,idObj)\n
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
else :\n
\n
    # Creation response XML\n
    if not message_error :\n
\n
        RESPONSE.setHeader(\'Cache-control\',\'pre-check=0,post-check=0,must-revalidate,s-maxage=0,max-age=0,no-cache\')\n
        RESPONSE.setHeader(\'Content-type\', \'text/xml; charset=utf-8\')\n
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
            <value> <string>connectorPlone.py</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
