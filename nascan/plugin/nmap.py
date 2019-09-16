# coding:utf-8
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException


class nmap:
    def __init__(self, task_host, port_list):
        self.ip = task_host
        self.port_list = port_list
        self.config_ini = {}
        self.nse_dict = {'102': 's7-info', '502': 'modbus-discover', '1911': 'fox-info',
			'9600': 'omron-info', '20000': 'dnp3-info', '44818': 'enip-info'}

    @classmethod
    def port_scan(cls, host, port_list, options):
        port_str = '-p'
        if port_list and len(port_list):
            port_str = port_str + str(port_list[0])
            for port in port_list[1:]:
                port_str += ','+str(port)
        else:
            return None

        nm_host = NmapProcess(targets=str(host), options=port_str+' '+options)
        nm_host.run()
        try:
            nm_report = NmapParser.parse(nm_host.stdout)
        except NmapParserException:
            return None

        open_ports = []
        for report_host in nm_report.hosts:
            for serv in report_host.services:
                if 'open' == serv.state:
                    open_ports.append(serv.port)

        return open_ports