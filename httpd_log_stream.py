import ncsa_log
import apache_log
import sys
from m.common import MiningError
from m._runtime import isVerbose

from m.io_targets.log_stream import iRaw

def parseUrlFromLog(rec):
    from http_parsers import Url
    return Url(rec.url)

class iHttpdLogStream(iRaw):
    def __init__(self, formatObj, recordClass, varName, fileHandler):
        self.formatObj = formatObj
        self.recordClass = recordClass
        self.varName = varName
        self.failed = 0
        self.total = 0
        iRaw.__init__(self, fileHandler)
    def next(self):
        try:
            while True:
                line = iRaw.next(self)[0]
                match = self.formatObj.match(line)
                if match:
                    return (self.recordClass(self.formatObj, line, match),)
                else:
                    self.failed += 1
                self.total += 1
        except StopIteration:
            if self.failed and isVerbose():
                print "Failed to match %d out of %d records" % (self.failed, self.total)
            raise

    def getVariableNames(self):
        return [self.varName]

class oHttpdLogStream(object):
    def __init__(self, httpdLogVarName, fileName, variableNames):
        try:
            self.index = variableNames.index(httpdLogVarName)
        except ValueError:
            raise MiningError("'%s' variable is not available at output" % httpdLogVarName)
        self.myFileName = fileName
        if fileName == "stdout":
            self.myFileHandler = sys.stdout
        else:
            self.myFileHandler = open(fileName, "wb")
        self.myVars = variableNames
    def save(self, record):
        print >>self.myFileHandler, record[self.index].line
    def close(self):
        if self.myFileHandler != sys.stdout:
            self.myFileHandler.close()

class iNCSALogStream(iHttpdLogStream):
    def __init__(self, fileHandler):
        clf = ncsa_log.NCSALogFormat()
        iHttpdLogStream.__init__(self, clf, ncsa_log.NCSALogRecord, "ncsa_log", fileHandler)

class oNCSALogStream(oHttpdLogStream):
    def __init__(self, fileName, variableNames):
        oHttpdLogStream.__init__(self, "ncsa_log", fileName, variableNames)

class iApacheLogStream(iHttpdLogStream):
    def __init__(self, fileHandler, format="common"):
        alf = apache_log.ApacheLogFormat(format)
        iHttpdLogStream.__init__(self, alf, apache_log.ApacheLogRecord, "apache_log", fileHandler)

class oApacheLogStream(oHttpdLogStream):
    def __init__(self, fileName, variableNames):
        oHttpdLogStream.__init__(self, "apache_log", fileName, variableNames)

