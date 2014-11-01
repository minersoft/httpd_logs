# 
# Copyright Michael Groys, 2014
#

from ncsa_log import NCSALogFormat, NCSALogRecord, FieldNotDefinedException
from m.utilities import mergeDictionaries
import re

class ApacheLogFormat(NCSALogFormat):
    idpattern = r"\>?[a-zA-Z]|\{[-\w]+\}[ieoC]"

    # continue field numbering after NCSA basic fields 
    START_FIELD = NCSALogFormat.NUM_FIELDS
    FLD_REMOTE_IP =           START_FIELD
    FLD_LOCAL_IP =            START_FIELD+1
    FLD_DURATION_USEC =       START_FIELD+2
    FLD_FILENAME =            START_FIELD+3
    FLD_KEEPALIVE_NUM =       START_FIELD+4
    FLD_PORT =                START_FIELD+5
    FLD_WORKER_PID =          START_FIELD+6
    FLD_QUERY_STRING =        START_FIELD+7
    FLD_HANDLER =             START_FIELD+8
    FLD_DURATION_SEC =        START_FIELD+9
    FLD_DEFINED_SERVER_NAME = START_FIELD+10
    FLD_SERVER_NAME =         START_FIELD+11
    FLD_CONNECTION_STATUS =   START_FIELD+12
    FLD_RECEIVED_BYTES =      START_FIELD+13
    FLD_SENT_BYTES =          START_FIELD+14
    FLD_USER_AGENT =          START_FIELD+15
    FLD_REFERER =             START_FIELD+16
    FLD_CONTENT_TYPE =        START_FIELD+17
    FLD_CONTENT_LENGTH =      START_FIELD+18
    NUM_FIELDS =              START_FIELD+19

    ourFieldReferences = {
        "a": [("remoteIp",  FLD_REMOTE_IP)],
        "A": [("localIp",  FLD_LOCAL_IP)],
        "B": [("bytesZero", NCSALogFormat.FLD_NUMBYTES)],
        "D": [("durationUsec", FLD_DURATION_USEC)],
        "f": [("filename", FLD_FILENAME)],
        "H": [("protocol", NCSALogFormat.FLD_PROTOCOL)],
        "k": [("keepaliveNum", FLD_KEEPALIVE_NUM)],
        "m": [("method", NCSALogFormat.FLD_METHOD)],
        "p": [("port", FLD_PORT)],
        "P": [("workerPid", FLD_WORKER_PID)],
        "q": [("queryString", NCSALogFormat.FLD_QUERY_STRING)],
        "R": [("handler", FLD_HANDLER)],
        "T": [("durationSec", FLD_DURATION_SEC)],
        "U": [("urlPath", NCSALogFormat.FLD_URL_PATH)],
        "v": [("definedServerName", FLD_DEFINED_SERVER_NAME)],
        "V": [("serverName", FLD_SERVER_NAME)],
        "X": [("connectionStatus", FLD_CONNECTION_STATUS)],
        "I": [("receivedBytes", FLD_RECEIVED_BYTES)],
        "O": [("sentBytes", FLD_SENT_BYTES)],
        "{User-agent}i":[("_User_agent_i", FLD_USER_AGENT)],
        "{Referer}i": [("_Referer_i", FLD_REFERER)],
        "{Content-type}o": [("_Content_type_o", FLD_CONTENT_TYPE)],
        "{Content-length}o": [("_Content_length_o", FLD_CONTENT_LENGTH)],
    }

    fieldReferences = mergeDictionaries(NCSALogFormat.fieldReferences, ourFieldReferences)
    
    ourFieldPatterns = {
        "a":  r"(?P<remoteIp>\d+\.\d+\.\d+\.d+|[0-9a-fA-F:]+)",
        "A":  r"(?P<localIp>\d+\.\d+\.\d+\.d+|[0-9a-fA-F:]+)",
        "B":  r"(?P<bytesZero>\d+)",
        "D":  r"(?P<durationUsec>\d+)",
        "f":  r"(?P<filename>[^\s]+)",
        "H":  r"(?P<protocol>[\w/.]+)",
        "k":  r"(?P<keepaliveNum>\d+)",
        "m":  r"(?P<method>[A-Z]+)",
        "p":  r"(?P<port>\d+)",
        "P":  r"(?P<workerPid>\d+)",
        "q":  r"(?P<queryString>\?[^\s]+|)",
        "R":  r"(?P<handler>[^\s]+)",
        "T":  r"(?P<durationSec>\d+)",
        "U":  r"(?P<urlPath>[^\s?]+)",
        "v":  r"(?P<definedServerName>[^\s]+)",
        "V":  r"(?P<serverName>[^\s]+)",
        "X":  r"(?P<connectionStatus>[-X+])",
        "I":  r"(?P<receivedBytes>\d+)",
        "O":  r"(?P<sentBytes>\d+)",
        "{User-agent}i": r"(?P<_User_agent_i>[^\"]*)",
        "{Referer}i": r"(?P<_Referer_i>[^\s]+|-)",
        "{Content-type}o": r"(?P<_Content_type_o>[^\"]+|-)",
        "{Content-length}o": r"(?P<_Content_length_o>\d+|-)",
    }

    fieldPatterns = mergeDictionaries(NCSALogFormat.fieldPatterns, ourFieldPatterns)
    # exceptional fields have both direct access  and  access via corresponding container
    exceptionalFields = set(["{User-agent}i", "{Referer}i", "{Content-type}o", "{Content-length}o"])
    
    predefinedFormats = {
        "common": "%h %l %u %t \"%r\" %>s %b",
        "vcommon": "%v %h %l %u %t \"%r\" %>s %b",
        "extended": "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"",
        "combined": "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"",
    }
    
    def __init__(self, formatStr):
        self.inputHdrFields = {}
        self.outputHdrFields = {}
        self.envFields = {}
        self.cookieFields = {}
        resolved = ApacheLogFormat.predefinedFormats.get(formatStr)
        if resolved:
            formatStr = resolved
        NCSALogFormat.__init__(self, formatStr)
    
    fieldSubRE = re.compile("[-{}]")
    def getCollectionFieldGroupName(self, field):
        return ApacheLogFormat.fieldSubRE.sub("_", field)
    
    def getPattern(self, field, default):
        if field.startswith("{"):
            if field in self.__class__.exceptionalFields:
                pattern = NCSALogFormat.getPattern(self, field, default)
            elif len(field)>3 and (field[-2:] in ["}i", "}o", "}e", "}c"]):
                groupName =self.getCollectionFieldGroupName(field) 
                pattern =  r"(?P<%s>.*)" % groupName
            else:
                pattern = default
        else:
            pattern = NCSALogFormat.getPattern(self, field, default)
        return pattern

    def registerFieldReferences(self, field):
        NCSALogFormat.registerFieldReferences(self, field)
        if len(field)>3:
            if field[-2:] == "}i":
                self.addReference(self.getCollectionFieldGroupName(field), self.inputHdrFields, field[1:-2])
            elif field[-2:] == "}o":
                self.addReference(self.getCollectionFieldGroupName(field), self.outputHdrFields, field[1:-2])
            elif field[-2:] == "}e":
                self.addReference(self.getCollectionFieldGroupName(field), self.envHdrFields, field[1:-2])
            elif field[-2:] == "}C":
                self.addReference(self.getCollectionFieldGroupName(field), self.cookieHdrFields, field[1:-2])
            
    def getInputHdrField(self, fieldName, matchObj):
        groupId = self.inputHdrFields.get(fieldName)
        if fieldName is None:
            raise FieldNotDefinedException(fieldName)
        else:
            return matchObj.group(groupId)
    def hasInputHdrField(self,fieldName):
        return fieldName in self.inputHdrFields

    def getOutputHdrField(self, fieldName, matchObj):
        groupId = self.outputHdrFields.get(fieldName)
        if fieldName is None:
            raise FieldNotDefinedException(fieldName)
        else:
            return matchObj.group(groupId)
    def hasOutputHdrField(self,fieldName):
        return fieldName in self.outputHdrFields

    def getEnvHdrField(self, fieldName, matchObj):
        groupId = self.envHdrFields.get(fieldName)
        if fieldName is None:
            raise FieldNotDefinedException(fieldName)
        else:
            return matchObj.group(groupId)
    def hasEnvHdrField(self,fieldName):
        return fieldName in self.envHdrFields

    def getCookieHdrField(self, fieldName, matchObj):
        groupId = self.cookieHdrFields.get(fieldName)
        if fieldName is None:
            raise FieldNotDefinedException(fieldName)
        else:
            return matchObj.group(groupId)
    def hasCookieHdrField(self,fieldName):
        return fieldName in self.cookieHdrFields


class ApacheLogRecord(NCSALogRecord):
    def __init__(self, format, line, match=None):
        NCSALogRecord.__init__(self, format, line, match)
    
    def inputHdrField(self, fieldName):
        return self._format.getInputHdrField(fieldName, self._match)
    
    def outputHdrField(self, fieldName):
        return self._format.getOutputHdrField(fieldName, self._match)

    def envHdrField(self, fieldName):
        return self._format.getEnvHdrField(fieldName, self._match)

    def cookieHdrField(self, fieldName):
        return self._format.getCookieHdrField(fieldName, self._match)

    @property
    def remoteIp(self):
        return self._format.getField(ApacheLogFormat.FLD_REMOTE_IP, self._match)

    @property
    def localIp(self):
        return self._format.getField(ApacheLogFormat.FLD_LOCAL_IP, self._match)

    @property
    def durationUsecAsStr(self):
        return self._format.getField(ApacheLogFormat.FLD_DURATION_USEC, self._match)
    @property
    def durationUsec(self):
        val = self.durationUsecAsStr
        return 0 if val=="-" else int(val)
    
    @property
    def durationSecAsStr(self):
        return self._format.getField(ApacheLogFormat.FLD_DURATION_SEC, self._match)
    @property
    def durationSec(self):
        val = self.durationSecAsStr
        return 0 if val=="-" else int(val)

    @property
    def duration(self):
        if self._format.hasField(ApacheLogFormat.FLD_DURATION_USEC):
            return self.durationUsec/1000000.
        return float(self.durationSec)
    
    @property
    def filename(self):
        return self._format.getField(ApacheLogFormat.FLD_FILENAME, self._match)

    @property
    def keepaliveNumAsStr(self):
        return self._format.getField(ApacheLogFormat.FLD_KEEPALIVE_NUM, self._match)
    @property
    def keepaliveNum(self):
        val = self.keepaliveNumAsStr
        return 0 if val=="-" else int(val)

    @property
    def portAsStr(self):
        return self._format.getField(ApacheLogFormat.FLD_PORT, self._match)
    @property
    def port(self):
        val = self.portAsStr
        return 0 if val=="-" else int(val)

    @property
    def workerPidAsStr(self):
        return self._format.getField(ApacheLogFormat.FLD_WORKER_PID, self._match)
    @property
    def workerPid(self):
        val = self.workerPidAsStr
        return 0 if val=="-" else int(val)

    @property
    def handler(self):
        return self._format.getField(ApacheLogFormat.FLD_HANDLER, self._match)

    @property
    def definedServerName(self):
        return self._format.getField(ApacheLogFormat.FLD_DEFINED_SERVER_NAME, self._match)

    @property
    def serverName(self):
        return self._format.getField(ApacheLogFormat.FLD_SERVER_NAME, self._match)

    @property
    def connectionStatus(self):
        return self._format.getField(ApacheLogFormat.FLD_CONNECTION_STATUS, self._match)

    @property
    def receivedBytesAsStr(self):
        return self._format.getField(ApacheLogFormat.FLD_RECEIVED_BYTES, self._match)
    @property
    def receivedBytes(self):
        val = self.receivedBytesAsStr
        return 0 if val=="-" else int(val)
    @property
    def sentBytesAsStr(self):
        return self._format.getField(ApacheLogFormat.FLD_SENT_BYTES, self._match)
    @property
    def sentBytes(self):
        val = self.sentBytesAsStr
        return 0 if val=="-" else int(val)

    @property
    def userAgent(self):
        return self._format.getField(ApacheLogFormat.FLD_USER_AGENT, self._match)

    @property
    def referer(self):
        return self._format.getField(ApacheLogFormat.FLD_REFERER, self._match)

    @property
    def contentType(self):
        return self._format.getField(ApacheLogFormat.FLD_CONTENT_TYPE, self._match)

    @property
    def contentLengthAsStr(self):
        return self._format.getField(ApacheLogFormat.FLD_CONTENT_LENGTH, self._match)

    @property
    def contentLength(self):
        val = self.contentLengthAsStr
        return -1 if val=="-" else int(val)

def getTestApacheRecord():
    alf = ApacheLogFormat(formatStr = "extended")
    line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"'
    
    return ApacheLogRecord(alf, line)

def getTestCustomApacheRecord():
    alf = ApacheLogFormat(formatStr = "%t %Dusec %h \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\" \"%{Content-type}o\" %{Content-length}o")
    line = '[30/Oct/2014:23:28:19 +0200] 134usec 127.0.0.1 "GET http://www.host.com/path?query HTTP/1.1" 301 248 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0" "text/html; charset=ISO-8859-4" 1000'
    return ApacheLogRecord(alf, line)

def test():
    import m.ut_utils as ut
    ut.START_TEST("apache_log_basic")
    record = getTestApacheRecord()
    ut.EXPECT_EQ("", "record.queryString")
    ut.EXPECT_EQ("http://www.example.com/start.html", "record.referer")
    ut.EXPECT_EQ("Mozilla/4.08 [en] (Win98; I ;Nav)", "record.userAgent")
    ut.EXPECT_EQ("http://www.example.com/start.html", "record.inputHdrField('Referer')")
    ut.EXPECT_EQ("Mozilla/4.08 [en] (Win98; I ;Nav)", "record.inputHdrField('User-agent')")
    
    ut.EXPECT_EQ("127.0.0.1", "record.remoteHost")

    ut.END_TEST()
    
    ut.START_TEST("apache_log_custom")
    record = getTestCustomApacheRecord()
    ut.EXPECT_EQ("?query", "record.queryString")
    ut.EXPECT_EQ("/path", "record.urlPath")
    ut.EXPECT_EQ("http://www.host.com", "record.urlRoot")
    ut.EXPECT_EQ("-", "record.referer")
    ut.EXPECT_EQ(134e-6, "record.duration")
    ut.EXPECT_EQ("Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0", "record.userAgent")
    ut.EXPECT_EQ("text/html; charset=ISO-8859-4", "record.contentType")
    ut.EXPECT_EQ(1000, "record.contentLength")
    ut.END_TEST()