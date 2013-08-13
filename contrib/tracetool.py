#!/usr/bin/env python
#
#
import argparse
import datetime
import gzip
import json
import sys
import zlib
from collections import defaultdict
from gpfstrace.analyze import TraceParser
from IPython import embed

def tree():
    return defaultdict(tree)

def main(args):

    filters = args.filters

    if args.traceinput:     # this currently crashes on my vm...
        t = gzip.open(args.traceinput, 'r')
        tracelog = json.load(t)
        parser = TraceParser(tracelog)
    else:
        #tracelog = lambda: defaultdict(tracelog)
        tracelog = tree()
        parser = TraceParser(tracelog)
        parser.parse_trace(args.filename, filters)

    # write the io dictionary to a compressed file in json format
    if args.tojson:
        gzipout = gzip.open(args.tojson, 'wb')
        json.dump(tracelog, gzipout)
        gzipout.close()

    if args.interactive:
        embed()

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--filename',
                        dest='filename',
                        required=False,
                        help='filename of the trace to open.')
    parser.add_argument('-i', '--interactive',
                        dest='interactive',
                        required=False,
                        action='store_true',
                        default=False,
                        help='interactive mode. open an ipython shell at the end...')
    parser.add_argument('-t', '--traceinput',
                        dest='traceinput',
                        required=False,
                        help='instead of reading a tracefile, pass in a json dump.')
    parser.add_argument('--filters',
                        dest='filters',
                        required=False,
                        default='io',
                        help='command sep list of filters. Valid values: ' + \
                            'io,ts,rdma,brl')
    parser.add_argument('--tojson',
                        dest='tojson',
                        required=False,
                        help='write dictionary to a json file')
    args = parser.parse_args()

    main(args)
