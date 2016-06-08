"""
Parse XML file containing MSDN structure documentation.

Author: Bingchang, Liu
Copyright 2016 VARAS, IIE of CAS

TODO: License

Based on Fireeye's' code at
https://github.com/fireeye/flare-ida
"""
import os.path
import sys
import xml.sax.handler
import itertools
import logging



class ParsingException(Exception):

    def __init__(self, message):
        super(ParsingException, self).__init__(message)
        self.message = message
        

class Member:

    def __init__(self):
        self.name = ""
        self.description = ""
        self.constants = []
        self.enums = []
        self._logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def __str__(self):
        return ("(%s, %s): %s" % (self.name, self.enums, self.description)).encode("utf-8")

    def __repr__(self):
        return self.__str__()

    def get_constant(self, name):
        for const in self.constants:
            if const.name == name:
                return const
        return None
        
    def merge(self, new_member):
        if self.name != new_member.name:
            return

        if new_member.description:
            self._logger.debug('   Overwriting member description')
            self.description = new_member.description
        if new_member.constants:
            for constant in new_member.constants:
                current_const = self.get_constant(constant.name)
                if not current_const:
                    # Constant not in list yet
                    self._logger.debug('   Adding new constant ' + constant.name)
                    self.constants.append(constant)
                    continue
                # Constant possibly needs to be updated
                current_const.merge(constant)
        if new_member.enums:
            self._logger.debug('   Merging member enums, resulting in [' + \
                               ', '.join(self.enums) + ']')
            self.enums += new_member.enums
            
            
class Constant:

    def __init__(self):
        self.name = ""
        self.value = ""
        self.description = ""
        self._logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def __str__(self):
        return ("(%s, %s)" % (self.name, self.value)).encode("utf-8")

    def __repr__(self):
        return self.__str__()

    def merge(self, new_constant):
        if self.name != new_constant.name:
            return

        self._logger.debug('   Working on constant ' + self.name)
        if new_constant.value:
            self._logger.debug('    Overwriting constant value')
            self.value = new_constant.value
        if new_constant.description:
            self._logger.debug('    Overwriting constant description')
            self.description = new_constant.description
            
            
class Structure:

    def __init__(self):
        self.name = ""
        self.dll = ""
        self.description = ""
        self.members = []
        self.returns = ""
        self._logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def __str__(self):
        return ("%s -- %s" % (self.name, unicode(self.members.__str__(),"utf-8"))).encode("utf-8")

    def __repr__(self):
        return self.__str__()

    def get_member(self, name):
        for member in self.members:
            if member.name == name:
                return member
        return None
        
    def merge(self, new_structure):
        """
        Merge two structure objects. Information found in the second structure
        instance will overwrite previously obtained data.

        Argument: 
        new_structure -- structure object that will overwrite previous data
        """
        if self.name != new_structure.name:
            return
        
        self._logger.debug('Merging structure ' + self.name)
        if new_structure.dll:
            self._logger.debug(' Overwriting structure DLL info')
            self.dll = new_structure.dll
        if new_structure.description:
            self._logger.debug(' Overwriting structure description')
            self.description = new_structure.description
        if new_structure.members:
            for member in new_structure.members:
                self._logger.debug('  Working on member ' + member.name)
                current_member = self.get_member(member.name)
                if not current_member:
                    # Member not in list yet
                    self._logger.debug('  Adding member ' + member.name + ' to members')
                    self.members.append(member)
                    continue
                # Member possibly needs to be updated
                current_member.merge(member)
                

class StructureHandler(xml.sax.handler.ContentHandler):
    c = itertools.count()
    IN_STRUCTRURE = next(c)
    IN_STRUCTURE_NAME = next(c)
    IN_DLL = next(c)
    IN_STRUCTURE_DESCRIPTION = next(c)
    IN_MEMBERS = next(c)
    IN_MEMBER = next(c)
    IN_MEMBER_NAME = next(c)
    IN_MEMBER_DESCRIPTION = next(c)
    IN_CONSTANTS = next(c)
    IN_CONSTANT = next(c)
    IN_CONSTANT_NAME = next(c)
    IN_CONSTANT_VALUE = next(c)
    IN_CONSTANT_DESCRIPTION = next(c)
    
    def __init__(self):
        self.inTitle = 0
        self.mapping = {}
        self.current_step = 0
        self.structures = []
        self._logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def startElement(self, name, attributes):
        if name == "msdn":
            pass
        elif name == "structures":
            pass
        elif name == "structure":
            self.current_step = StructureHandler.IN_STRUCTRURE
            self.structure = Structure()
        elif self.current_step == StructureHandler.IN_STRUCTRURE and name == "name":
            self.current_step = StructureHandler.IN_STRUCTURE_NAME
        elif self.current_step == StructureHandler.IN_MEMBER and name == "name":
            self.current_step = StructureHandler.IN_MEMBER_NAME
        elif name == "dll":
            self.current_step = StructureHandler.IN_DLL
        elif self.current_step == StructureHandler.IN_STRUCTRURE and name == "description":
            self.current_step = StructureHandler.IN_STRUCTURE_DESCRIPTION
        elif self.current_step == StructureHandler.IN_MEMBER and name == "description":
            self.current_step = StructureHandler.IN_MEMBER_DESCRIPTION
        elif self.current_step == StructureHandler.IN_CONSTANT and name == "name":
            self.current_step = StructureHandler.IN_CONSTANT_NAME
        elif self.current_step == StructureHandler.IN_CONSTANT and name == "value":
            self.current_step = StructureHandler.IN_CONSTANT_VALUE
        elif self.current_step == StructureHandler.IN_CONSTANT and name == "description":
            self.current_step = StructureHandler.IN_CONSTANT_DESCRIPTION
        elif name == "members":
            self.current_step = StructureHandler.IN_MEMBERS
        elif name == "member":
            self.current_step = StructureHandler.IN_MEMBER
            self.current_member = Member()
        elif self.current_step == StructureHandler.IN_CONSTANTS and name == "constant":
            self.current_step = StructureHandler.IN_CONSTANT
            self.current_constant = Constant()
        elif name == "constants":
            self.current_step = StructureHandler.IN_CONSTANTS
            self.current_member.enums = []
            if "enums" in attributes.getNames():
                enums = attributes.getValue('enums').encode('utf-8')
                if enums:
                    self.current_member.enums = enums.split(',')
        else:
            self._logger.warning('Error START: ' + name)
            raise ParsingException('start')
    
    def characters(self, data):
        if self.current_step == StructureHandler.IN_STRUCTURE_NAME:
            self.structure.name = self.structure.name + data
        elif self.current_step == StructureHandler.IN_DLL:
            self.structure.dll = self.structure.dll + data
        elif self.current_step == StructureHandler.IN_STRUCTURE_DESCRIPTION:
            self.structure.description = self.structure.description + data
        elif self.current_step == StructureHandler.IN_MEMBER_NAME:
            self.current_member.name = self.current_member.name + data
        elif self.current_step == StructureHandler.IN_MEMBER_DESCRIPTION:
            self.current_member.description = self.current_member.description + \
                data
        elif self.current_step == StructureHandler.IN_CONSTANT_NAME:
            self.current_constant.name = self.current_constant.name + data
        elif self.current_step == StructureHandler.IN_CONSTANT_VALUE:
            self.current_constant.value = self.current_constant.value + data
        elif self.current_step == StructureHandler.IN_CONSTANT_DESCRIPTION:
            self.current_constant.description = self.current_constant.description + \
                data
           
    def endElement(self, name):
        if name in ["structures", "msdn"]:
            pass
        elif name == "structure":
            self.structures.append(self.structure)
        elif self.current_step in [StructureHandler.IN_MEMBER_NAME, StructureHandler.IN_MEMBER_DESCRIPTION]:
            self.current_step = StructureHandler.IN_MEMBER
        elif self.current_step in [StructureHandler.IN_CONSTANT_NAME, StructureHandler.IN_CONSTANT_VALUE, StructureHandler.IN_CONSTANT_DESCRIPTION]:
            self.current_step = StructureHandler.IN_CONSTANT
        elif name in ["name", "dll", "description", "members", "constants"]:
            self.current_step = StructureHandler.IN_STRUCTRURE
        elif name == "member":
            self.current_step = StructureHandler.IN_MEMBER
            self.structure.members.append(self.current_member)
        elif name == "constant":
            self.current_step = StructureHandler.IN_CONSTANTS
            self.current_member.constants.append(self.current_constant)
        else:
            self._logger.warning('Error END: ' + name)
            raise ParsingException('end')
            
        
g_logger = logging.getLogger(__name__)
            
def parse(xmlfile):
    """
    Return parsed MSDN information.

    Argument:
    xmlfile -- xml data file storing the MSDN information
    """
    g_logger.info('Starting parsing ' + xmlfile)
    parser = xml.sax.make_parser()
    try:
        handler = StructureHandler()
    except ParsingException as e:
        g_logger.warning(e.message)
        return None # TODO critical?
    parser.setContentHandler(handler)
    parser.parse(xmlfile)
    return handler.structures 
