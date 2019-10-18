# coding:utf-8
import threading
import time
import sys
reload(sys)
sys.setdefaultencoding('utf8')
mutex = threading.Lock()
def write(scan_type, host, port, info):
    mutex.acquire()
    port = int(port)
    try:
        time_str = time.strftime('%X', time.localtime(time.time()))
        if scan_type == 'portscan':
            print "[%s] %s:%d open" % (time_str, host, port)
        elif scan_type == 'server':
            print "[%s] %s:%d is %s" % (time_str, host, port, str(info))
        elif scan_type == 'web':
            print "[%s] %s:%d is web" % (time_str, host, port)
            print "[%s] %s:%d web info %s" % (time_str, host, port, info)
        elif scan_type == 'active':
            print "[%s] %s active" % (time_str, host)
        elif scan_type == 'info':
            print "[%s] %s" % (time_str, info)
        elif scan_type == 'nmap_error':
            print "[%s] %s:%d nmap error: %s" % (time_str, host, port, info)
        elif scan_type == 'nmap_vul':
            print "[%s] %s:%d find vul: %s" % (time_str, host, port, info)
    except Exception, e:
        print 'logerror',e
        pass
    sys.stdout.flush()
    mutex.release()
