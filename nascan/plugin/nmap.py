# coding:utf-8
from lib import mongo, log
import json
import datetime
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException


class nmap:
    def __init__(self, task_host, port_list, config_ini):
        self.ip = str(task_host)
        self.port_list = [str(port) for port in port_list]
        self.config_ini = config_ini
        self.nse_dict = {'102': 's7-info', '502': 'modbus-discover', '1911': 'fox-info',
			'9600': 'omron-info', '20000': 'dnp3-info', '44818': 'enip-info'}
        if self.config_ini['Nse_list']:
            for nse in self.config_ini['Nse_list'].split('\n'):
                nse_port = str(nse.split('|')[0])
                nse_script = str(nse.split('|')[1])
                self.nse_dict[nse_port] = nse_script

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

    def run(self):
        if not self.host_discern():
            return
        
        port_info = {}
        for port in self.port_list:
            port_info = self.server_discern(port)
            if port_info:
                self.check_vul(port_info)

    def host_discern(self):
        nm_host = NmapProcess(targets=self.ip, options='-O -v');
        nm_host.run()
        if nm_host.has_failed():
           log.write('nmap_error', self.ip, 0, '(failed) '+nm_host.stderr)
           return False
        try:
            nm_report = NmapParser.parse(nm_host.stdout)
        except NmapParserException:
           log.write('nmap_error', self.ip, 0, '(parsing) '+nm_host.stdout)
           return False
        host_report = nm_report.hosts[0]

        if not host_report.is_up():
            return False

        log.write('info', self.ip, 0, str(self.ip)+' is up')
        time_ = datetime.datetime.now()
        mongo.NA_HOST.update({'ip': self.ip},
                            {"$set": {
                                'hostname': ''.join(host_report.hostnames),
                                'mac': host_report.mac,
                                'vendor': host_report.vendor,
                                'time': time_,
                                'OS': host_report.os_class_probabilities()[0].description
                                    if host_report.os_class_probabilities() else 'unknown'
                                }
                            },
                            upsert=True)
        return True

    def server_discern(self, port):
        nm_options = '-p' + port + ' '
        if str(port) in self.nse_dict.keys():
            nm_options += '--script ' + self.nse_dict[str(port)] + ' '
        else:
            nm_options += '--script ' + 'banner' + ' '
        nm_host = NmapProcess(targets=self.ip, options=nm_options)
        nm_host.run()
        if nm_host.has_failed():
            log.write('nmap_error', self.ip, port, '(failed) '+nm_host.stderr)
            return None
        try:
            nm_report = NmapParser.parse(nm_host.stdout)
        except NmapParserException:
            log.write('nmap_error', self.ip, port, '(parsing) '+nm_host.stdout)
            return None
        serv_report = nm_report.hosts[0].services[0]

        if not serv_report.open():
            return None

        # record nse result into database
        time_ = datetime.datetime.now()
        date_ = time_.strftime('%Y-%m-%d')
        nm_update = {
            "ip": self.ip,
            "port": port,
            "server": serv_report.service if serv_report.service else 'unknown',
            "time": time_
        }
        if serv_report.scripts_results:
            for _dict in serv_report.scripts_results:
                nm_update[_dict['id']] = json.dumps(_dict['elements'])

        history_info = mongo.NA_INFO.find_one_and_delete({
            "ip": self.ip, "port": port})
        log.write("server", self.ip, port, nm_update['server'])
        mongo.NA_INFO.insert(nm_update)
        if history_info:
            self.statistics[date_]['update'] += 1
            del history_info["_id"]
            history_info['del_time'] = time_
            history_info['type'] = 'update'
            mongo.NA_HISTORY.insert(history_info)
        else:
            self.statistics[date_]['add'] += 1

        return nm_update

    def check_vul(self, port_info):
        # use only service of port_info to check vul at this stage
        # may add more match with vul in the future
        if not 'server' in port_info.keys():
            return
        
        port = port_info['port']
        service = port_info['server']
        if service == 'unknown':
            return

        docs = mongo.NA_PLUGIN.find({'$or': [
            {'keyword': {'$regex': str(service).lower()}},
            {'filename': {'$regex': str(service).lower()}},
            {'name': {'$regex': str(service).lower()}},
            {'info': {'$regex': str(service).lower()}}
        ]})

        for doc in docs:
            log.write('nmap_vul', self.ip, port,
                str(doc['level']) + '-' + str(doc['name']))