#
# Copyright Michael Groys, 2014
#
from httpd_log_format import *

class NCSALogFormat(LogFormat):
    delimiter = "%"
    idpattern = r"\>?[_a-zA-Z][_a-zA-Z0-9]*"
    fieldPatterns = {
        "h":  r"(?P<remoteHost>[^\s]*)",
        "l":  r"(?P<logname>[^\s]*)",
        "u":  r"(?P<userid>[^\s]*)",
        "t":  r"\[(?P<time>(?P<localtime>\d+/[a-zA-Z]+/\d\d\d\d:\d\d:\d\d:\d\d)\s+(?P<gmtoffset>(\+|-)?\d\d\d\d))\]",
        "r":  r"(?P<request>(?P<requestMethod>[A-Z]+)\s+(?P<requestUrlRoot>[a-z]+://[^/]+)?(?P<requestUrl>(?P<requestUrlPath>[^\s?]+)(?P<requestQueryString>\?[^\s]*|))\s+(?P<requestProtocol>[\w/.]+))",
        ">s": r"(?P<status>\d+|-)",
        "s":  r"(?P<firstStatus>\d+|-)",
        "b":  r"(?P<bytes>\d+|-)",
    }
    COMMON_FORMAT = "%h %l %u %t \"%r\" %>s %b"

    FLD_REMOTE_HOST = 0
    FLD_LOGNAME = 1
    FLD_USERID = 2
    FLD_FULLTIME = 3
    FLD_LOCALTIME = 4
    FLD_GMTOFFSET = 5
    FLD_REQUEST = 6
    FLD_METHOD = 7
    FLD_URL = 8
    FLD_PROTOCOL = 9
    FLD_STATUS = 10
    FLD_NUMBYTES = 11
    FLD_QUERY_STRING = 12
    FLD_URL_PATH = 13
    FLD_URL_ROOT = 14
    NUM_FIELDS = 15

    fieldReferences = {
        "h": [("remoteHost",  FLD_REMOTE_HOST)],
        "l": [("logname", FLD_LOGNAME)],
        "u": [("userid", FLD_USERID)],
        "t": [("time", FLD_FULLTIME), ("localtime", FLD_LOCALTIME), ("gmtoffset", FLD_GMTOFFSET)],
        "r": [("request", FLD_REQUEST), ("requestMethod", FLD_METHOD), ("requestUrl", FLD_URL), ("requestProtocol", FLD_PROTOCOL), \
              ("requestUrlRoot", FLD_URL_ROOT), ("requestUrlPath", FLD_URL_PATH), ("requestQueryString", FLD_QUERY_STRING)],
        ">s": [("status", FLD_STATUS)],
        "s": [("firstStatus", FLD_STATUS)],
        "b": [("bytes", FLD_NUMBYTES)],
    }
    
    def __init__(self, formatStr = COMMON_FORMAT):
        LogFormat.__init__(self, formatStr)
        self.fieldToGroupId = [None]*self.__class__.NUM_FIELDS
        self.createMatch()
    
    def registerFieldReferences(self, field):
        refs = self.__class__.fieldReferences.get(field)
        if not refs:
            return
        for groupName, fldId in refs:
            toolsLog.info("Adding for field '%s' group=%s id=%s", field, groupName, fldId)
            self.addReference(groupName, self.fieldToGroupId, fldId)

    def getField(self, fieldId, matchObj):
        groupId = self.fieldToGroupId[fieldId]
        if groupId is None:
            raise FieldNotDefinedException(self.getFieldName(fieldId))
        else:
            return matchObj.group(groupId)
    
    def hasField(self,fieldId):
        return self.fieldToGroupId[fieldId] is not None

    def getFieldName(self, fieldId):
        for refs in self.__class__.fieldReferences.itervalues():
            for name, refFieldId in refs:
                if refFieldId == fieldId:
                    return name
        return str(fieldId)

class NCSALogRecord(object):
    def __init__(self, format, line, match=None):
        self._format = format
        self.line = line
        self._match = match if match else format.match(line)

    @property
    def remoteHost(self):
        return self._format.getField(NCSALogFormat.FLD_REMOTE_HOST, self._match)
    @property
    def logname(self):
        return self._format.getField(NCSALogFormat.FLD_LOGNAME, self._match)
    @property
    def userid(self):
        return self._format.getField(NCSALogFormat.FLD_USERID, self._match)
    @property
    def fulltimeAsStr(self):
        return self._format.getField(NCSALogFormat.FLD_FULLTIME, self._match)
    @property
    def localtimeAsStr(self):
        return self._format.getField(NCSALogFormat.FLD_LOCALTIME, self._match)
    @property
    def localtimeAsStruct(self):
        val = self.localtimeAsStr
        return time.strptime(val, "%d/%b/%Y:%H:%M:%S")
    @property
    def gmtime(self):
        from calendar import timegm
        val = self.localtimeAsStruct
        return timegm(val) - self.gmtoffset
    @property
    def gmtoffsetAsStr(self):
        return self._format.getField(NCSALogFormat.FLD_GMTOFFSET, self._match)
    @property
    def gmtoffset(self):
        val = self.gmtoffsetAsStr
        sign = 1
        if val[0] == "+":
            val = val[1:]
        elif val[0] == "-":
            val = val[1:]
            sign = -1
        return sign * (int(val[0:2],10)*3600 + int(val[2:4],10)*60) 
    @property
    def request(self):
        return self._format.getField(NCSALogFormat.FLD_REQUEST, self._match)
    @property
    def method(self):
        return self._format.getField(NCSALogFormat.FLD_METHOD, self._match)
    @property
    def url(self):
        return self._format.getField(NCSALogFormat.FLD_URL, self._match)
    @property
    def protocol(self):
        return self._format.getField(NCSALogFormat.FLD_PROTOCOL, self._match)
    @property
    def statusAsStr(self):
        return self._format.getField(NCSALogFormat.FLD_STATUS, self._match)
    @property
    def status(self):
        val = self.statusAsStr
        if val=="-":
            return 0
        else:
            return int(val)
    @property
    def numbytesAsStr(self):
        return self._format.getField(NCSALogFormat.FLD_NUMBYTES, self._match)
    @property
    def numbytes(self):
        val = self.numbytesAsStr
        if val=="-":
            return 0
        else:
            return int(val)
    @property
    def urlPath(self):
        return self._format.getField(NCSALogFormat.FLD_URL_PATH, self._match)
    @property
    def urlRoot(self):
        return self._format.getField(NCSALogFormat.FLD_URL_ROOT, self._match)
    @property
    def queryString(self):
        return self._format.getField(NCSALogFormat.FLD_QUERY_STRING, self._match)

    def __str__(self):
        return "[%s] %s \"%s\" -> %s %s" % (self.fulltimeAsStr, self.remoteHost, self.request, self.statusAsStr, self.numbytesAsStr)

def getTestNCSARecord():
    clf = NCSALogFormat()
    line = "127.0.0.1 user-identifier frank [10/Oct/2000:13:55:00 -0730] \"GET /path/script.php?q=val HTTP/1.0\" 200 2326"
    
    return NCSALogRecord(clf, line)

def test():
    import m.ut_utils as ut
    ut.START_TEST("ncsa-log")
    record = getTestNCSARecord()
    
    ut.EXPECT_EQ("127.0.0.1", "record.remoteHost")
    ut.EXPECT_EQ("user-identifier", "record.logname")
    ut.EXPECT_EQ("frank", "record.userid")
    ut.EXPECT_EQ("10/Oct/2000:13:55:00", "record.localtimeAsStr")
    ut.EXPECT_EQ(-(7*3600+30*60), "record.gmtoffset", msg="offset should be -0730 in sec")
    ut.EXPECT_EQ(971213100, "record.gmtime", "Time is 2000/10/10 21:25:00 in GMT")
    ut.EXPECT_EQ("/path/script.php?q=val", "record.url")
    ut.EXPECT_EQ("/path/script.php", "record.urlPath")
    ut.EXPECT_EQ(None, "record.urlRoot")
    ut.EXPECT_EQ("?q=val", "record.queryString")
    ut.END_TEST()