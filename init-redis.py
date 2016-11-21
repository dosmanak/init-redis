#!/usr/bin/env python
import argparse
from logging.handlers import SysLogHandler
import logging
from hmac import HMAC as MD5
import socket
import errno
import re

def netcat(hostname, port, content):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((hostname, port))
        s.sendall(content+"\r\n")
        s.shutdown(socket.SHUT_WR)
        data = ""
        while 1:
            chunk = s.recv(1024)
            data += chunk
            if not chunk:
                l.debug("Received: %d bytes from %s:%d"%(len(data),hostname,port))
                break
        s.close()
        return data
    except Exception as e:
        l.error("Communication with %s:%d failed. %s"%(hostname, port, e.args[1]))
        exit(-1*e.args[0])

class MyLogger(logging.Logger):
    def __init__(self,name="pylogger", stderr=0, verbosity=0):
        super(MyLogger, self).__init__(name,max(10,30-verbosity*10))
        formatter = logging.Formatter(name+":(%(levelname)s) %(message)s")
        if stderr:
            handler = logging.StreamHandler()
        else:
            handler = SysLogHandler(address="/dev/log", facility=SysLogHandler.LOG_USER)
        handler.setFormatter(formatter)
        self.addHandler(handler)
        self.__stderr = stderr
    def error(self, message):
        ''' print errors to stdout in addition to syslog if defined'''
        if self.__stderr == 0:
            print "(ERROR) "+message
        super(MyLogger, self).error(message)

class Redis_server:
    def __init__(self, host, port=6379):
        if ":" in host:
            self.host , self.port = host.split(":")
            self.port = int(self.port)
        else:
            self.host = host
            self.port = port
        try:
            self.ip = socket.gethostbyname(self.host)
        except Exception as e:
            l.error("Communication with %s:%d failed. %s"%(self.host, self.port, e.args[1]))
            exit(-1*e.args[0])


    def __get_repl_info(self):
        redis_command = "info replication"
        return netcat(self.host,self.port,redis_command)

    def __parse_line(self,want_know,line):
        d = {}
        for key in want_know:
            if key in line:
                d[key] = line[len(key)+1:]
        return d

    def is_master(self):
        return True if "role:master" in self.__get_repl_info() else False

    def get_server_info(self):
        """ parse redis info replication into nice dictionary """
        self.info = {}
        repl_info_lines = self.__get_repl_info().splitlines()
        if self.is_master():
            slave_regex = re.compile("slave[0-9]*:ip")
            for line in repl_info_lines:
                self.info.update( self.__parse_line(["role","connected_slaves"], line) )
                # match slave name extended with ":ip" for precise match
                # "ip" must be edited in string
                match_slave = slave_regex.match(line)
                if match_slave:
                    slave_items = [item.split("=") for item in\
                            ("ip"+slave_regex.split(line)[1]).split(",")]
                    self.info[match_slave.group()[0:-3]] =\
                            { d[0]:d[1] for d in slave_items }
        # Else is slave
        else:
            for line in repl_info_lines:
                self.info.update( 
                        self.__parse_line(["role","master_host","master_port",\
                                "connected_slaves","master_link_status"], line))
        return self.info

    def set_slaveof(self,master_host,master_port=None):
        master_port = self.port if master_port is None else master_port
        redis_command = "slaveof %s %d"%(master_host, master_port)
        return netcat(self.host, self.port, redis_command)

    def set_master(self):
        redis_command = "slaveof NO ONE"
        return netcat(self.host, self.port, redis_command)

class Redis_sentinel:
    def __init__(self, host, port=26379):
        if ":" in host:
            self.host , self.port = host.split(":")
            self.port = int(self.port)
        else:
            self.host = host
            self.port = port
    def get_masters(self):
        """ parse redis info sentinel masters into nice dictionary """
        self.info = {}
        redis_command = "info sentinel"
        sent_info_lines = netcat(self.host, self.port, redis_command).splitlines()
        master_regex = re.compile("master[0-9]*:name")
        for line in sent_info_lines:
            match_master = master_regex.match(line)
            if match_master:
                master_items = [item.split("=") for item in\
                        ("name"+master_regex.split(line)[1]).split(",")]
                self.info[match_master.group()[0:-5]] =\
                        { d[0]:d[1] for d in master_items }
        return self.info

    def remove_masters(self):
        redis_command_prefix = "sentinel remove "
        resp = "+OK"
        for m in self.get_masters().values():
            resp = netcat(self.host, self.port, redis_command_prefix + m["name"])
        if resp.strip() != "+OK":
            raise EnvironmentError(errno.EBADE,\
                    "%s:%d Unexpected sentinel response (%s), %s"\
                    %(self.host,self.port,master,resp))

    def set_monitor(self, master_name, quorum, master_ip, master_port=None):
        master_port = self.port if master_port is None else master_port
        redis_command = "sentinel monitor %s %s %d %d"\
                %(master_name, master_ip, master_port, quorum)
        resp = netcat(self.host, self.port, redis_command)
        if resp.strip() not in [ "+OK", "-ERR Duplicated master name" ]:
            raise EnvironmentError(errno.EBADE,"Unexpected sentinel response")

#### MAIN ####
if __name__ == "__main__":
    programname = "init-redis"
    programname = argparse._os.path.basename(argparse._os.sys.argv[0])

# Parse arguments
    p = argparse.ArgumentParser(prog=programname)
    required = p.add_argument_group('required arguments')
    required.add_argument("--servers",nargs="+",required=True,\
            action="append",metavar="SERVER")
    required.add_argument("--quorum",required=True, type=int)
    p.add_argument("--sentinels",nargs="+",action="append",metavar="SENTINEL")
    p.add_argument("--groupmaster",default="redis",metavar="NAME",\
            help="master group name")
    p.add_argument("-v",help="verbosity (repeat for more verbose log)",action="count",default=0)
    p.add_argument("-stderr", help=argparse.SUPPRESS,action="store_true")

    args=p.parse_args()
    if len(args.servers) > 1:
            p.error("--servers appear several times.")
    if args.sentinels and len(args.sentinels) > 1:
            p.error("--sentinels appear several times.")

    l = MyLogger(programname,args.stderr,args.v)
    servers = [Redis_server(item) for sublist in args.servers for item in sublist]
    sentinels = [Redis_sentinel(item) for sublist in args.sentinels for item in sublist] if args.sentinels else []

# Sanity check on servers.
    master_count=0
    slave_master_set = set()
    # Detect master in first loop
    for s in servers:
        if s.is_master():
            master_count += 1
            # Add correct master to slave_master_set to check slaves are configured well
            l.debug("Master: "+s.ip+":"+str(s.port))
            slave_master_set.add(
                    MD5(s.ip+":"+str(s.port)).hexdigest()
                    )

    for s in servers:
        if not s.is_master():
            info = s.get_server_info()
            l.debug("Watched master "+info["master_host"]+":"+s.info["master_port"])
            slave_master_set.add(
                    MD5(s.info["master_host"]+":"+s.info["master_port"]).hexdigest()
                    )

# Configure if wrong master count or slaves misconfigured
    if master_count == 1 and len(slave_master_set) == 1:
        l.info("Master and slaves are already configured.")
    else:
        l.warning("New master must be elected")
        l.debug("master_count: %d",master_count)
        l.debug("len(slave_master_set): %d", len(slave_master_set))
        l.debug(slave_master_set)
        servers[0].set_master()
        # Other must be slaves
        for s in servers[1:]:
            s.set_slaveof(servers[0].ip,servers[0].port)

# Sanity check on sentinels
# Each sentinel can monitor more masters, the basic check is that all sentinels have the same masters
# which can be checked using md5
    check_sentinels = set()
    for s in sentinels:
        masters = s.get_masters()
        if masters:
            check_sentinels.add( MD5(str(masters)).hexdigest() )
        else:
            check_sentinels.add(None)

    if check_sentinels != set([None]) and len(check_sentinels) == 1:
        l.info("All sentinels have same masters")
    else:
        l.warning("Sentinels must be configured")
        config_needed = True
        # Now we are sure there is only one master
        for server in servers:
            if server.is_master():
                for s in sentinels:
                    s.remove_masters()
                    s.set_monitor(args.mastername, args.quorum, server.ip, server.port)
                break # master already detected break here
    
    from pprint import pformat
    level = logging.DEBUG
    for s in servers:
        l.log(level,"# Server %s:%d\n%s"%(s.host, s.port,pformat(s.get_server_info())))
    for s in sentinels:
        l.log(level,"# Sentinel %s:%d\n%s"%(s.host, s.port,pformat(s.get_masters())))
