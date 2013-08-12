#!/usr/bin/env python
#
#
import argparse
import datetime
import gzip
import json
import sys
from collections import defaultdict
from gpfstrace.analyze import TraceParser
from IPython import embed


def tree():
    return defaultdict(tree)

def main(args):

    tracelog = tree()
    
    try:
        parser = TraceParser(tracelog)
        parser.parse_trace(args.filename)
    except AttributeError as ae:
        print "Error: {0}".format(ae)
        from IPython import embed; embed()
        sys.exit(0)

    # write the io dictionary to a file in json format
    if args.tojson:
        json.dump(tracelog, open(args.tojson, 'w'))

    from IPython import embed; embed()

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--filename',
                        dest='filename',
                        required=True,
                        help='filename of the trace to open.')
    parser.add_argument('--tojson',
                        dest='tojson',
                        required=False,
                        help='write dictionary to a json file')
    args = parser.parse_args()

    main(args)
