##############################################################################
#
# Copyright (c) 2010 Nexedi SARL and Contributors. All Rights Reserved.
#                    Daniele Vanbaelinghem <daniele@nexedi.com>
#
# WARNING: This program as such is intended to be used by professional
# programmers who take the whole responsability of assessing all potential
# consequences resulting from its eventual inadequacies and bugs
# End users who are looking for a ready-to-use solution with commercial
# garantees and support are strongly adviced to contract a Free Software
# Service Company
#
# This program is Free Software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
##############################################################################

import zope.interface
from AccessControl import ClassSecurityInfo
from Products.ERP5Type.Globals import PersistentMapping
from Products.ERP5Type import Permissions, interfaces
from Products.ERP5.Document.IdGenerator import IdGenerator

from zLOG import LOG, INFO

class ZODBContinuousIncreasingIdGenerator(IdGenerator):
  """
    Create some Ids with the zodb storage
  """
  zope.interface.implements(interfaces.IIdGenerator)
  # CMF Type Definition
  meta_type = 'ERP5 ZODB Continous Increasing Id Generator'
  portal_type = 'ZODB Continous Increasing Id Generator'
  add_permission = Permissions.AddPortalContent

  # Declarative security
  security = ClassSecurityInfo()
  security.declareObjectProtected(Permissions.AccessContentsInformation)

  def _generateNewId(self, id_group, id_count=1, default=None):
    """
     Return the new_id from the last_id of the zodb
     Use int to store the last_id, use also a persistant mapping for to be
     persistent.
    """
    if id_group in (None, 'None'):
      raise ValueError, '%s is not a valid group Id.' % (repr(id_group), )
    if default is None:
      default = 0
    self.last_id_dict = getattr(self, 'last_id_dict', None)
    if self.last_id_dict is None:
      # If the dictionary not exist initialize generator
      self.initializeGenerator()
    marker = []
    # Retrieve the last id
    last_id = self.last_id_dict.get(id_group, marker)
    if last_id is marker:
      new_id = default
      if id_count > 1:
        # If create a list use the default and increment
        new_id = new_id + id_count - 1
    else:
      # Increment the last_id
      new_id = last_id + id_count
    # Store the new_id in the dictionary
    self.last_id_dict[id_group] = new_id
    return new_id

  security.declareProtected(Permissions.AccessContentsInformation,
      'generateNewId')
  def generateNewId(self, id_group=None, default=None):
    """
      Generate the next id in the sequence of ids of a particular group
    """
    new_id = self._generateNewId(id_group=id_group, default=default)
    return new_id

  security.declareProtected(Permissions.AccessContentsInformation,
      'generateNewIdList')
  def generateNewIdList(self, id_group=None, id_count=1, default=None):
    """
      Generate a list of next ids in the sequence of ids of a particular group
    """
    new_id = self._generateNewId(id_group=id_group, id_count=id_count, \
                                 default=default)
    return range(new_id - id_count + 1, new_id + 1)

  security.declareProtected(Permissions.AccessContentsInformation,
      'initializeGenerator')
  def initializeGenerator(self):
    """
      Initialize generator. This is mostly used when a new ERP5 site
      is created. Some generators will need to do some initialization like
      prepare some data in ZODB
    """
    LOG('initialize ZODB Generator', INFO, 'Id Generator: %s' % (self,))
    if getattr(self, 'last_id_dict', None) is None:
      self.last_id_dict = PersistentMapping()

    # XXX compatiblity code below, dump the old dictionnaries
    portal_ids = getattr(self, 'portal_ids', None)
    # Dump the dict_ids dictionary
    if getattr(portal_ids, 'dict_ids', None) is not None:
      for id_group, last_id in portal_ids.dict_ids.items():
        if self.last_id_dict.has_key(id_group) and \
           self.last_id_dict[id_group] > last_id:
          continue
        self.last_id_dict[id_group] = last_id

  security.declareProtected(Permissions.AccessContentsInformation,
      'clearGenerator')
  def clearGenerator(self):
    """
      Clear generators data. This can be usefull when working on a
      development instance or in some other rare cases. This will
      loose data and must be use with caution

      This can be incompatible with some particular generator implementation,
      in this case a particular error will be raised (to be determined and
      added here)
    """
    # Remove dictionary
    self.last_id_dict = PersistentMapping()

  security.declareProtected(Permissions.ModifyPortalContent,
      'exportGeneratorIdDict')
  def exportGeneratorIdDict(self):
    """
      Export last id values in a dictionnary in the form { group_id : last_id }
    """
    return dict(self.last_id_dict)

  security.declareProtected(Permissions.ModifyPortalContent,
      'importGeneratorIdDict')
  def importGeneratorIdDict(self, id_dict, clear=False):
    """
      Import data, this is usefull if we want to replace a generator by
      another one.
    """
    if clear:
      self.clearGenerator()
    if not isinstance(id_dict, dict):
      raise TypeError, 'the argument given is not a dictionary'
    for value in id_dict.values():
      if not isinstance(value, int):
        raise TypeError, 'the value given in dictionary is not a integer'
    self.last_id_dict.update(id_dict)
