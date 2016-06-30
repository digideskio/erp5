##############################################################################
# Copyright (c) 2016 Nexedi SA and Contributors. All Rights Reserved.
#
# WARNING: This program as such is intended to be used by professional
# programmers who take the whole responsibility of assessing all potential
# consequences resulting from its eventual inadequacies and bugs
# End users who are looking for a ready-to-use solution with commercial
# guarantees and support are strongly advised to contract a Free Software
# Service Company
#
# This program is Free Software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
##############################################################################

from AccessControl import getSecurityManager
from AccessControl.PermissionRole import rolesForPermissionOn
from Acquisition import aq_base
from App.special_dtml import DTMLFile
from Products.CMFCore.Expression import Expression
from . import _dtmldir

def getRoles(ob, sm):
  stack = sm._context.stack
  if stack:
    proxy_roles = getattr(stack[-1], '_proxy_roles', None)
    if proxy_roles:
      return set(proxy_roles)
  return set(sm.getUser().getRolesInContext(ob))

class Guard:

  permissions = ()
  roles = ()
  groups = ()
  expr = None
  proxy = None

  guardForm = DTMLFile('guard', _dtmldir)

  def __call__(self, ob):
    if self.proxy:
      return getattr(ob, self.proxy).checkGuard()
    sm = getSecurityManager()
    # returns 1 if self passes against ob, else 0.
    if self.permissions:
      # Require at least one role for required roles for the given permission.
      isdisjoint = getRoles(ob, sm).isdisjoint
      for p in self.permissions:
        if not isdisjoint(rolesForPermissionOn(p, ob)):
          break
      else:
        if self.roles and isdisjoint(self.roles):
          # Require at least one of the given roles.
          return 0
    elif self.roles and getRoles(ob, sm).isdisjoint(self.roles):
      # Require at least one of the given roles.
      return 0
    if self.groups:
      # Require at least one of the specified groups.
      u = sm.getUser()
      b = aq_base(u)
      if hasattr(b, 'getGroupsInContext'):
        u_groups = u.getGroupsInContext(ob)
      elif hasattr(b, 'getGroups'):
        u_groups = u.getGroups()
      else:
        u_groups = ()
      for group in self.groups:
        if group in u_groups:
          break
      else:
        return 0
    return self.expr is None or self.expr(createExpressionContext(ob))

  @classmethod
  def _edit(cls, ob, attr, props):
    self = getattr(ob, attr)
    add = self is None
    if isinstance(self, cls):
      change = 0
    else:
      change = not add
      self = cls()
    if props is None:
      props = {}
    for x in 'proxy', 'permissions', 'roles', 'groups', 'expr':
      new = props.get('guard_' + x, '').strip()
      old = getattr(self, x)
      if x == 'expr':
        old = getattr(old, 'text', '')
      elif x != 'proxy':
        new = tuple(new.strip() for new in new.split(';')) if new else ()
      elif not new:
        new = None
      if new != old:
        if new:
          setattr(self, x, Expression(new) if x == 'expr' else new)
          if x == 'proxy':
            props = {}
        else:
          delattr(self, x)
        change = 1
      if x in self.__dict__:
        add = 1
    if not add:
      delattr(ob, attr)
    elif change:
      setattr(ob, attr, self)

  def getPermissionsText(self):
    return '; '.join(self.permissions)

  def getRolesText(self):
    return '; '.join(self.roles)

  def getGroupsText(self):
    return '; '.join(self.groups)

  def getExprText(self):
    return getattr(self.expr, 'text', '')

  # TODO: getProxyText & dtml
