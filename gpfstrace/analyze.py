import argparse
import datetime
import gzip
import json
import sys
from collections import defaultdict 
from IPython import embed


class TraceParser(object):

    def __init__(self, tracelog):
        self.tracelog = tracelog
        self._SECTOR_SIZE = 512

        # some regexes to filter out lines we don't want
        self.IORegex = ['QIO:', 'SIO:', 'FIO:']
        self.TSRegex = ['tscHandleMsgDirectly:', 'tscSendReply:', 'sendMessage',
                        'tscSend:', 'tscHandleMsg:']
        self._FILTER_MAP = {
                        'io':   'TRACE_IO',
                        'rdma': 'TRACE_RDMA',
                        'ts':   'TRACE_TS',
                        'brl':  'TRACE_BRL' 
        }


    def parse_trace(self, filename, filters=None):

        try:
            # create a filter list
            filter_list = [self._FILTER_MAP[i] for i in filters.split(',')]
        except KeyError as ke:
            print "Error, filter ({0}) is not a valid filter.".format(ke)
            print "Please use the following filters: {0}".format(
                    self._FILTER_MAP.keys())
            sys.exit(1)

        # open the trace report file
        try:
            f = gzip.open(filename, 'rb')
        except IOError as ioe:
            # maybe it's not a zipfile?
            f = open(filename, 'r')

        skip = 0
        trace_start = 0

        for line in f:

            # grab the date from the first line to use it later...
            if skip == 0:
                ld = line.split()[2:]   # longdate
                datearg = "{0}-{1}-{2} {3}:{4}:{5}".format(ld[-1], ld[1], 
                        ld[2], ld[3].split(':')[0], ld[3].split(':')[1], 
                        ld[3].split(':')[2])
                # will be in epoch time...
                self.trace_start_epoch = int(datetime.datetime.strptime(
                            datearg, '%Y-%b-%d %H:%M:%S').strftime('%s'))
                skip += 1
                continue
            elif skip == 1:
                ld = line.split()[3:]   # longdate
                datearg = "{0}-{1}-{2} {3}:{4}:{5}".format(ld[-1], ld[1], 
                        ld[2], ld[3].split(':')[0], ld[3].split(':')[1], 
                        ld[3].split(':')[2])
                # will be in epoch time...
                self.trace_stop_epoch = int(datetime.datetime.strptime(
                            datearg, '%Y-%b-%d %H:%M:%S').strftime('%s'))
                skip += 1
                continue
            # this is to skip the lines 3-8. shameful to say the least...
            elif skip > 1 and skip < 8:
                skip += 1
                continue
            elif line.split()[2].strip(':') not in filter_list:
                # skip any lines we don't want
                continue
            elif line.split()[2].strip(':') == 'TRACE_IO' and \
                line.split()[3] in self.IORegex:
                self._parse_io_trace(line)
            elif line.split()[2].strip(':') == 'TRACE_TS' and \
                line.split()[3] in self.TSRegex:
                self._parse_ts_trace(line)
            else:
                continue

        # assemble the stats for enabled filters
        if 'io' in filters.split(','):
            self._assemble_io_stats()
        #if 'ts' in filters.split(','):
        #   self._assemble_ts_stats()

        return

    def _parse_io_trace(self, line):
        """Parses lines with TRACE_IO"""

        op = line.split()[3].strip(':')
        pid = line.split()[1]
        l = line.split()
        traceref = self.tracelog['trace_io']

        # we will figure out the OID of the IO operation based on the
        #   disknum:diskaddr address, since that's the only thing that is
        #   the same between the 3 lines of an IO operation, queued (QIO),
        #   starting (SIO), finished (FIO)

        # the line formats vary, sigh...
        if op == 'QIO':
            #oid = l[17]
            oid = l[17]+":"+pid
            traceref[oid]['qio']['pid'] = pid
            traceref[oid]['qio']['tracetime'] = float(l[0])
            traceref[oid]['qio']['diskid'] = l[15]
            traceref[oid]['qio']['disknum'] = l[17].split(':')[0]
            traceref[oid]['qio']['diskaddr'] = l[17].split(':')[1]
            traceref[oid]['qio']['optype'] = ' '.join(l[4:6])
            traceref[oid]['qio']['nSectors'] = int(l[19])
            traceref[oid]['qio']['align'] = l[21]
            #traceref[oid]['qio']['line'] = line

            # get the IO tags
            traceref[oid]['qio']['tags'] = (l[7:9])

        elif op == 'SIO':
            #oid = l[12]
            oid = l[12]+":"+pid
            traceref[oid]['sio']['tracetime'] = float(l[0])
            traceref[oid]['sio']['pid'] = pid
            traceref[oid]['sio']['diskid'] = l[10]
            traceref[oid]['sio']['disknum'] = l[12].split(':')[0]
            traceref[oid]['sio']['diskaddr'] = l[12].split(':')[1]
            traceref[oid]['sio']['nSectors'] = int(l[14])
            #traceref[oid]['sio']['line'] = line

        elif op == 'FIO':
            #oid = l[17]
            oid = l[17]+":"+pid
            traceref[oid]['fio']['tracetime'] = float(l[0])
            traceref[oid]['fio']['pid'] = pid
            traceref[oid]['fio']['diskid'] = l[15]
            traceref[oid]['fio']['disknum'] = l[17].split(':')[0]
            traceref[oid]['fio']['diskaddr'] = l[17].split(':')[1]
            traceref[oid]['fio']['optype'] = ' '.join(l[4:6])
            traceref[oid]['fio']['nSectors'] = int(l[19])
            #traceref[oid]['fio']['finish_time'] = float(l[22])
            traceref[oid]['fio']['finish_time'] = self.trace_start_epoch + \
                traceref[oid]['fio']['tracetime']
            #traceref[oid]['fio']['line'] = line

            # get the IO tags
            traceref[oid]['fio']['tags'] = (l[7:9])

        return

    def _parse_ts_trace(self, line):
        """Parses lines with TRACE_TS"""

        op = line.split()[3].strip(':')
        pid = line.split()[1]
        l = line.split()

        # make nested dictionary traceref...
        traceref = self.tracelog['trace_ts']

        if op == 'tscHandleMsgDirectly':
            # we don't want the reply messages for now...
            if l[7].strip('\'').strip('\',') == 'reply':
                return

            msg_id = l[9].strip(',')
            oid = msg_id+':'+pid
            traceref[oid][op]['tracetime'] = float(l[0])
            traceref[oid][op]['pid'] = pid
            traceref[oid][op]['msg'] = l[7].strip('\'').strip('\',')
            traceref[oid][op]['msg_id'] = msg_id
            traceref[oid][op]['len'] = l[11]
            traceref[oid][op]['node_id'] = l[13]
            traceref[oid][op]['node_ip'] = l[14]
            #traceref[oid][op]['line'] = line

        elif op == 'tscSendReply':
            msg_id = l[9].strip(',')
            oid = msg_id+':'+pid
            traceref[oid][op]['tracetime'] = float(l[0])
            traceref[oid][op]['pid'] = pid
            traceref[oid][op]['msg'] = l[7].strip('\'').strip('\',')
            traceref[oid][op]['msg_id'] = msg_id
            traceref[oid][op]['replyLen'] = l[11]
            #traceref[oid][op]['line'] = line

        elif op == 'sendMessage':
            msg_id = l[9].strip(',')
            oid = msg_id+':'+pid
            traceref[oid][op]['tracetime'] = float(l[0])
            traceref[oid][op]['pid'] = pid
            traceref[oid][op]['node_id'] = l[5]
            traceref[oid][op]['node_ip'] = l[6]
            traceref[oid][op]['nodename'] = l[7].strip(':')
            traceref[oid][op]['msg_id'] = msg_id
            traceref[oid][op]['type'] = l[11]
            traceref[oid][op]['tagP'] = l[13]
            traceref[oid][op]['seq'] = l[15]
            traceref[oid][op]['state'] = l[17]
            #traceref[oid][op]['line'] = line

            # as a bonus, try to build an ip -> nodename table
            traceref['nodetable'][l[6]] = l[7].strip(':')

        elif op =='tscHandleMsg':
            msg_id = l[9].strip(',')
            oid = msg_id+':'+pid
            traceref[oid][op]['tracetime'] = float(l[0])
            traceref[oid][op]['pid'] = pid
            traceref[oid][op]['msg'] = l[7].strip('\'').strip('\',')
            traceref[oid][op]['msg_id'] = msg_id
            traceref[oid][op]['len'] = l[9]
            traceref[oid][op]['node_id'] = l[11]
            traceref[oid][op]['node_ip'] = l[12]
            #traceref[oid][op]['line'] = line

        elif op == 'tscSend':
            if "rc = 0x" in line:  # useless line
                return
            oid = l[13]+':'+pid
            traceref[oid][op]['tracetime'] = float(l[0])
            traceref[oid][op]['pid'] = pid
            traceref[oid][op]['msg'] = l[7].strip('\'').strip('\',')
            traceref[oid][op]['n_dest'] = l[9]
            traceref[oid][op]['data_len'] = l[11]
            traceref[oid][op]['msg_id'] = l[13]
            traceref[oid][op]['msg_buf'] = l[15]
            traceref[oid][op]['mr'] = l[17]

        else:
            # do nothing
            return

        
        return

    def _assemble_io_stats(self):
        """Takes raw tracelog dict and computes disk stats"""

        # okay, let's do something useful now
        for k in self.tracelog['trace_io'].keys():

            # some of the traces don't contain 'qio', 'sio' and 'fio'
            #   if so, don't bother looking at this...
            if not self.tracelog['trace_io'][k].has_key('fio'):
                continue
                        
            # the disk data was read/written to
            try:
                disk = int(self.tracelog['trace_io'][k]['fio']['disknum'])
                self.tracelog['trace_io'][k]['iosize'] = self.tracelog['trace_io'][k]['fio']['nSectors'] * self._SECTOR_SIZE
            except TypeError as te:
                print "Type error: {0}".format(te)
                print self.tracelog['trace_io'][k]

            # some of the client logs don't have QIO/SIO for certain things
            #   like log writes, so check for those...
            if self.tracelog['trace_io'][k].has_key('sio') and \
                    self.tracelog['trace_io'][k].has_key('fio'):
                self.tracelog['trace_io'][k]['iotime'] = self.tracelog['trace_io'][k]['fio']['tracetime'] - \
                                self.tracelog['trace_io'][k]['sio']['tracetime']
                self.tracelog['trace_io']['disks'][disk]['iotimes'].setdefault(disk, []).append(
                        float(self.tracelog['trace_io'][k]['iotime']))

            # figure out how long the IO was queued...
            if self.tracelog['trace_io'][k].has_key('qio') and \
                    self.tracelog['trace_io'][k].has_key('sio'):
                io_time_in_queue = self.tracelog['trace_io'][k]['sio']['tracetime'] - \
                                   self.tracelog['trace_io'][k]['qio']['tracetime']
                self.tracelog['trace_io'][k]['time_in_queue'] = io_time_in_queue

                # get the start time in epoch, since we now have the finish time (epoch)
                #   and the duration of the IO
                io_start_time = self.tracelog['trace_io'][k]['sio']['tracetime'] + self.trace_start_epoch
                io_queued_time = self.tracelog['trace_io'][k]['qio']['tracetime'] + self.trace_start_epoch
                self.tracelog['trace_io'][k]['sio']['start_time'] = io_start_time
                self.tracelog['trace_io'][k]['qio']['queued_time'] = io_queued_time

            # increment the disks bucket per FIO
            try:
                self.tracelog['trace_io']['disks'][disk]['num_iops'].setdefault(
                        disk, []).append(1)
                self.tracelog['trace_io']['disks'][disk]['iosizes'].setdefault(
                        disk, []).append(int(self.tracelog['trace_io'][k]['iosize']))
            except TypeError as te:
                print "Hit a bug: {0}".format(te)
                pass

            # find the longest IO time, and add the entire 
            #   IO op (QIO, SIO, FIO) to the disk dict
            if not self.tracelog['trace_io']['disks'][disk]['stats'].has_key('longest_io') or \
                self.tracelog['trace_io'][k]['iotime'] > self.tracelog['trace_io']['disks'][disk]['stats']['longest_io']:

                self.tracelog['trace_io']['disks'][disk]['stats']['longest_io'] = self.tracelog['trace_io'][k]['iotime']
                self.tracelog['trace_io']['disks'][disk]['stats']['longest_io_line'] = \
                    "{0}\n{1}\n{2}".format(self.tracelog['trace_io'][k]['qio']['line'],
                            self.tracelog['trace_io'][k]['sio']['line'],
                            self.tracelog['trace_io'][k]['fio']['line'])

        # calculate the average time per iop per disk and average io size
        for k, v in self.tracelog['trace_io']['disks'].iteritems():

            try:
                total_io_bytes = sum(v['iosizes'][k])
                total_io_time = sum(v['iotimes'][k])
                average_io_size = total_io_bytes / len(v['iosizes'][k])
                average_io_time = total_io_time / len(v['iotimes'][k])
                v['stats']['avg_io_tm'] = average_io_time
                v['stats']['avg_io_sz'] = average_io_size
                v['stats']['total_bytes_io'] = total_io_bytes
                v['stats']['total_time_io'] = total_io_time

                # so dirty, but it was late and I wanted to eat at 
                #   McDonald's and read People magazine, so I was in a hurry
                num_iops = len(v['num_iops'][k])
                self.tracelog['trace_io']['disks'][k].pop('num_iops', None) # delete that stupid list
                v['stats']['num_iops'] = num_iops
            except ZeroDivisionError as zde:
                print "Zero Division error: {0}".format(zde)
                continue

        return
 
    def _assemble_ts_stats(self):
        """Takes raw tracelog dict and computes ts stats"""

        # okay, let's do something useful now
        for k,v in self.tracelog['trace_ts'].iteritems():
           
            # messages received
            if v.has_key('tscHandleMsgDirectly'):
               
                try:
                    msg = v['tscHandleMsgDirectly']['msg']
                    fromwho = v['tscHandleMsgDirectly']['node_ip']

                    if not self.tracelog['trace_ts']['stats']['received'].has_key(msg):
                        self.tracelog['trace_ts']['stats']['received'][msg] = []

                    self.tracelog['trace_ts']['stats']['received'][msg].append(fromwho)
                except Exception as e:
                    print "Exception in 'received', '{0}'".format(e)
                    embed()
                    sys.exit(0)

            if v.has_key('tscHandleMsg'):
                try:
                    msg = v['tscHandleMsg']['msg']
                    fromwho = v['tscHandleMsg']['node_ip']

                    if not self.tracelog['trace_ts']['stats']['received'].has_key(msg):
                        self.tracelog['trace_ts']['stats']['received'][msg] = []

                    self.tracelog['trace_ts']['stats']['received'][msg].append(fromwho)
                except Exception as e:
                    print "Exception in 'received', '{0}'".format(e)
                    embed()
                    sys.exit(0)

            # messages sent
            if v.has_key('sendMessage'):

                try:
                    # need the 'msg' field from the tscSend operation
                    if v['tscSend'].has_key('msg'):
                        msg = v['tscSend']['msg']
                    else:
                        msg = v['tscSendReply']['msg']

                    towho = v['sendMessage']['node_ip']

                    if not self.tracelog['trace_ts']['stats']['sent'].has_key(msg):
                        self.tracelog['trace_ts']['stats']['sent'][msg] = []

                    self.tracelog['trace_ts']['stats']['sent'][msg].append(towho)
                except Exception as e:
                    print "Exception in 'sent', '{0}'".format(e)
                    embed()
                    sys.exit(0)


        return

    def print_disk_summary(self):
        """Print out a summary of disk statistics..."""

        # totals
        total_bytes = 0
        total_iops = 0
        trace_elapsed_secs = self.trace_stop_epoch - self.trace_start_epoch

        print "Disk Summary:"
        print "*"*80
        # summarize some disk stats
        for k in sorted(self.tracelog['trace_io']['disks'].keys()):
            formatstr = "Disk: {0}, IOPS: {1}, Avg_IO_T: {2:.3f}, " + \
                "Avg_IO_Sz: {3}, Longest_IO: {4:.3f}, Total_Bytes: {5}, " + \
                "Total_IO_Time: {6:.3f}"
            try:
                print formatstr.format(
                k, self.tracelog['trace_io']['disks'][k]['stats']['num_iops'], 
                self.tracelog['trace_io']['disks'][k]['stats']['avg_io_tm'],
                self.tracelog['trace_io']['disks'][k]['stats']['avg_io_sz'], 
                self.tracelog['trace_io']['disks'][k]['stats']['longest_io'],
                self.tracelog['trace_io']['disks'][k]['stats']['total_bytes_io'],
                self.tracelog['trace_io']['disks'][k]['stats']['total_time_io'])
            except ValueError as ve:
                continue

            # gather some totals
            total_bytes += self.tracelog['trace_io']['disks'][k]['stats']['total_bytes_io']
            total_iops += self.tracelog['trace_io']['disks'][k]['stats']['num_iops']

        print
        print
        print "Totals:"
        print "*"*80
        print "Total Gigabytes Read/Written: {0}".format(float(total_bytes) / 1024 / 1024 / 1024)
        print "Total IO Operations: {0}".format(total_iops)
        print "Total IO Trace Time: {0} secs".format(trace_elapsed_secs)
        print "Total GB/s: {0:.3f}".format(
                float(total_bytes / 1024 / 1024 / 1024) / float(trace_elapsed_secs))

