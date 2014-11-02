#
# Copyright Michael Groys, 2014
#
import string
import re
import time
from m.loggers import toolsLog

class LogFormat(string.Template):
    #delimeter = "$"
    #idpattern = "[_a-z][_a-z0-9]*"
    fieldPatterns = {} # defines pattern for each known field in format "(?P<id>.*)"
    def __init__(self, format):
        string.Template.__init__(self, format)
        self._matchRef = []
        self.regexpStr = None
        self.regexp = None
    
    def addReference(self, groupName, collection, index):
        self._matchRef.append( (groupName, collection, index) )
    
    def createMatch(self):
        self.regexpStr = self.substitute(self)
        toolsLog.info("created regexp '%s'", self.regexpStr)
        self.regexp = re.compile(self.regexpStr)
        for groupName, collection, index in self._matchRef:
            collection[index] = self.regexp.groupindex[groupName]

    def __getitem__(self, field):
        self.registerFieldReferences(field)
        return self.getPattern(field, "(.*)")
    def get(self, field, default=None):
        self.registerFieldReferences(field)
        return self.getPattern(field, default)
    def match(self, logLine):
        return self.regexp.match(logLine)
    # abstract function that should be implemented in child
    # It adds references to all named groups that appear in the field substitution
    def registerFieldReferences(self, field):
        raise NotImplemented()
    # can be overridden by child to use different field-to-pattern substitution mechanism 
    def getPattern(self, field, default):
        return self.__class__.fieldPatterns.get(field, default)

class FieldNotDefinedException(Exception):
    def __init__(self, fieldName=""):
        Exception.__init__(self)
        self.fieldName = fieldName
    def __str__(self):
        return "Field %s is not defined" % self.fieldName
        
