import miner_globals
from ncsa_log import getTestNCSARecord    
from apache_log import getTestApacheRecord

# Completion symbols
ncsa_log = getTestNCSARecord()
miner_globals.addCompletionSymbol('ncsa_log', ncsa_log)
apache_log = getTestApacheRecord()
miner_globals.addCompletionSymbol('apache_log', apache_log)

# define targets
miner_globals.addTargetToClassMapping("ncsa_log", "httpd_log_stream.iNCSALogStream", "httpd_log_stream.oNCSALogStream", "reads NCSA formatted web server logs")
miner_globals.addTargetToClassMapping("apache_log", "httpd_log_stream.iApacheLogStream", "httpd_log_stream.oApacheLogStream", "reads apache formatted web server logs, allows custom formatting")

#parsers    
miner_globals.addParserMapping("url", "ncsa_log", "httpd_log_stream.parseUrlFromLog")
miner_globals.addParserMapping("url", "apache_log", "httpd_log_stream.parseUrlFromLog")
