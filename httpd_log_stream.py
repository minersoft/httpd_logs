import ncsa_log
import apache_log

from m.io_targets.log_stream import iRaw

def parseUrlFromLog(rec):
    from http_parsers import Url
    return Url(rec.url)

class iHttpdLogStram(iRaw):
    def __init__(self, formatObj, recordClass, varName, fileHandler):
        self.formatObj = formatObj
        self.recordClass = recordClass
        self.varName = varName
        self.failed = 0
        iRaw.__init__(self, fileHandler)
    def next(self):
        while True:
            line = iRaw.next(self)[0]
            match = self.formatObj.match(line)
            if match:
                return (self.recordClass(self.formatObj, line, match),)
            else:
                self.failed += 1
    def getVariableNames(self):
        return [self.varName]

class iNCSALogStream(iHttpdLogStram):
    def __init__(self, fileHandler):
        clf = ncsa_log.NCSALogFormat()
        iHttpdLogStram.__init__(self, clf, ncsa_log.NCSALogRecord, "ncsa_log", fileHandler)

class iApacheLogStream(iHttpdLogStram):
    def __init__(self, fileHandler, format="common"):
        alf = apache_log.ApacheLogFormat(format)
        iHttpdLogStram.__init__(self, alf, apache_log.ApacheLogRecord, "apache_log", fileHandler)
