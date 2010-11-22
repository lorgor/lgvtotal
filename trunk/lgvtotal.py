"""Usage:

lgvtotal.py [-h] [-d loglevel] [--help] [--debug=loglevel] [directory] [filename]... 

-h --help    Produce this help message.

-l loglevel --log=loglevel

             Specify the level of logging:
                debug, info, warning, error, critical.
             Logging is to standard output.

-r --restart Restart execution from last checkpoint. Do not specify
             directories if you are doing a restart. Execution will
             continue with last set of directories / files being
             processed.

             The history file is named lgvtotal.pkl and is located in
             the working directory. It is reused for each execution.

             Results are kept in the history file. Doing a restart
             once all processing is done will print out all results.

-a --noscan  Submit files directly without first checking if there is
             already a report at VirusTotal.

             If Volatility memory samples are being submitted, it is
             not likely that VirusTotal will have these already on
             record. So it is faster just to submit for scanning
             without trying to retrieve the corresponding report.

             (Default action) For normal operation (ie scanning executables stored on
             disk), VirusTotal likely has already seen the file. So
             first the pgm tries to retrieve the corresponding
             file. If not found, then the file is submitted for
             scanning.

directory, filename

             Specify list of directories and / or individual files to
             be submitted to VirusTotal. If a directory is specified,
             note that all its subdirectories will be processed as
             well.

==Examples==

Scan a single file:

             python lgvtotal.py myfile.exe

Scan two directories containing samples of executables extracted by Volatility from volatile memory:

             python lgvtotal.py -k ~/tmp/volatility_results/exec_dirs*

Do a restart:

             cd my_working_directory_for_the_previous_execution
             python lgvtotal.py --restart

Debug output:
             python lgvtotal.py -l "debug"

Scan a list of filenames:
             cat my_file_list | xargs python lgvtotal.py
"""


# Virustotal API automation based on work by Lobe and bboe - sample
# Python code from VTotal API site
#
# See API docs @ http://www.virustotal.com/advanced.html for the API reference.
#
# Copyright (c) November 2010, Loren Gordon
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
#     * notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
#     * copyright notice, this list of conditions and the following
#     * disclaimer in the documentation and/or other materials
#     * provided with the distribution.  Neither the name of Loren
#     * Gordon nor the names of other contributors, nor any companies
#     * of which Loren Gordon is an employee may be used to endorse or
#     * promote products derived from this software without specific
#     * prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# Imports

import simplejson
import urllib
import urllib2
import urlparse

import os
import sys
import hashlib

import getopt

from collections import deque
import logging
import time
import pprint

import cPickle

# Globals and constants


API_KEY = "Your VirusTotal API Key here"


MAX_FILESIZE = 20               # 20 MB file max
MAX_SUB = 20                    # Maximum of 20 requests submitted per
REQ_INTVL = 300                 #    each 5 min (300 sec) interval
SLEEP_INTVL = 30                # Sleep interval (sec) before checking the q's again
MAX_ATTEMPTS = 10               # No more than 10 attempts with a given file

# Custom Exception Handlers

try:
    import posthandler
    post_opener = urllib2.build_opener(posthandler.MultipartPostHandler)
except ImportError:
    posthandler = None
        
class ModuleNotFound(Exception):
    ''' Module has not been found '''

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

class NameInvalid(Exception):
    """File or directory invalid specification"""

# Logging levels, default level for logging

LEVELS = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warning': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL}

class VTotApi(object):
    """ Wrapper class to handle interactions with VirusTotal API.
    Usage:
        import lgvtotal
        vtapi = lgvtotal.VTotApi()
        vtapi.get_report("85dae28ab8c2abfdbb9bfe7b58936cbd")
        vtapi.scan_file("myfilename.exe")

    API methods can be called like python functions:
        data = api.get_report(resource=RESOURCE_ID)

    API methods return python objects (Or an exception)
    So that constructs such as the following can be used:
          print data["permalink"]
    """
    global API_KEY

    _api_report_url = "https://www.virustotal.com/api/get_file_report.json"
    _api_scan_url = 'https://www.virustotal.com/api/scan_file.json'    

    def __init__(self):
        self.api_key = API_KEY
        self.pp = pprint.PrettyPrinter(indent=4)
       
    def get_report(self, fileid):
        """Use the VirusTotal API to access the report for a file.

        Input: fileid  VirusTotal File Identifier - either hash or permalink ID

        Calling the Virustotal API:
        In order to retrieve a scan report on a given file you must perform an
        HTTP POST request to the following URL:

        https://www.virustotal.com/api/get_file_report.json

        With the following two HTTP POST parameters:

        * resource: a md5/sha1/sha256 hash will retrieve the most recent
          report on a given sample. You may also specify a permalink
          identifier (sha256-timestamp as returned by the file upload API)
          to access a specific report.
        * key: your API key.
        """

        logging.debug("API get_report {0}".format(fileid))
        url = VTotApi._api_report_url
        parameters = {"resource": fileid, "key": self.api_key}

        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            returned = urllib2.urlopen(req).read()
        except (urllib2.HTTPError, urllib2.URLError):
            print "Http Error:", sys.exc_info()[0]
            json = {'result': -999}
        except:
            print "Unexpected error:", sys.exc_info()[0]
            json = {'result': -999}
            raise
        else:
            logging.debug(self.pp.pformat(returned))
            json = simplejson.loads(returned)    
        return json
        
    
    def scan_file(self, filename):
        """ Use the VirusTotal API to submit a file for scanning.

        Input: filename Name of file to be uploaded for scanning

        To send a file you must perform an HTTP POST request to the following URL:

        https://www.virustotal.com/api/scan_file.json

        This API call expects multipart/form-data parameters, the
        string part of the the call should have the following
        parameter:

        * key: your API key.

        The file part of the call should contain the name of the
        submitted file and the file itself.The API acts like a form
        with a file input field named file.
        """
        logging.debug("API scan_file {0}".format(filename))
        if not posthandler:
            raise ModuleNotFound("posthandler module needed to submit files")
        params = {'key' : self.api_key, 'file' : open(filename, "rb") }
        try:
            json = post_opener.open(VTotApi._api_scan_url, params).read()
        except (urllib2.HTTPError, urllib2.URLError):
            print "Http Error:", sys.exc_info()[0]
            json_ret = {'result': -999}
        except:
            print "Unexpected error:", sys.exc_info()[0]
            json_ret = {'result': -999}
            raise
        else:
            logging.debug(self.pp.pformat(json))
            json_ret = simplejson.loads(json)
        
        return json_ret

class VTotFile(object):
    """The VTotFile object contains essential file information and status.
    """
    
    def __init__(self, filename):
        """ Initialize the file object.
        """
        self.filename = filename
        self.numAV = 0         # # of AVs uses for testing
        self.numhits = 0       # # of AV that reported something
        self.rpt_date = ""     # Date of last VirusTotal report
        self.av_findings = {}  # Dictionary with individual AV reports
        self.file_md5 = ""     # MD5 file hash
        self.file_permalink = ""   # VirusTotal's "permaid" which is a sha256 hash
        self.numattempts = 0       # number of attempts made with this file
        # check that file is less than 20 MB (VirusTotal limit)
        filesizeMB = os.path.getsize(filename) / 1048576 
        if filesizeMB > 20:
            logging.critical("File {0} is too big. Filesize {1}MB exceeds 20MB".format(
                filename, filesizeMB))
            raise NameInvalid("File is too big. Filesize exceeds 20MB") 
        else:
            # compute the MD5 hash for this file
            fd = open(filename, 'rb')
            self.file_md5 = hashlib.md5(fd.read()).hexdigest()
            fd.close

    def get_results(self, data):
        """ Parse the json scan results and store in the file object
        """
        assert data['result'] == 1, 'get_results given invalid data - result not 1'
        self.file_permalink = data['permalink'] 
        rpt = data['report']
        self.rpt_date = rpt[0]    # First elt in the list is the report date
        self.av_findings = rpt[1] # 2cd elt is the actual dictionary with individual AV findings
        for av, finding in self.av_findings.iteritems():
            self.numAV = self.numAV + 1
            if finding != '':
                self.numhits = self.numhits + 1
            

    def prt_summary(self):
        """ Print a 1-line summary of scan results
        """
        logging.info('{0}: {1} / {2} {3}'.format(
            self.filename, self.numhits, self.numAV, self.rpt_date))
        return True

 
    def prt_detail(self):
        """ Print a detailed report for this file.
        """
        # First print the summary record. It this is ok, go for the details.
        if self.prt_summary() and self.numhits > 0:
            for av, finding in self.av_findings.iteritems():
                if finding != '':
                    print '{0:>10} {1} {2}'.format(" ", av, finding)
            print '{0:>10} Permalink: {1}'.format(" ", self.file_permalink)

class Worker(object):
    """ Worker class to manage file submission / retrieval results for all files in a directory 
    """
    global MAX_SUB, REQ_INTVL, SLEEP_INTVL, MAX_ATTEMPTS

    def __init__(self, scan_f):
        """ Verify that the directory exists, make it the working directory
        """
        logging.debug('Initializing worker class')
        self.reqnum = 0         # Number of requests active
        self.req_intvl = 0      # Time (sec) since start of current interval
        self.q_wait = deque()   # queue of elts waiting for submission
        self.q_process = deque() # queue of elts being processed
        self.q_done = deque()    # queue of elts finished
        self.q_err = deque()     # queue of elts not processed
        self.getrpt_before_scan_f = scan_f
                                # If True, then try to retrieve rpt
                                # before submitting for scan

        self.myapi = VTotApi()   # API handle

    def load_q(self, name):
        """ Add files to the wait queue
        """
        logging.debug('Loading the wait q with {0}'.format(name))
        if not os.path.exists(name):
            logging.critical("{0} does not exist".format(name))
            raise NameInvalid("File or directory does not exist")

        # add the contents of a directory to the wait queue
        if os.path.isdir(name):
            for (path, dirs, files) in os.walk(name):
                for file in files:
                    newfile = os.path.join(path, file)
                    self.load_q1(newfile)

        # add a single file to the wait queue
        elif os.path.isfile(name):
            self.load_q1(name)

        # not a file or directory 
        else:
            raise NameInvalid("Element is neither a file nor a directory")


    def load_q1(self,name):
        """ Sub-function to actually add a single file to the work q.
        """
        f_obj = VTotFile(name)
        logging.debug('Queue file for testing')
        self.q_wait.append(f_obj)
        logging.debug('File {0} added to wait q'.format(name))

    def run_q(self):
        """ If possible, submit some new work. Then check if in-process results are ready.
        """
        # Try to submit some new work
        logging.debug('Run the wait queue. reqnum {0}'.format(self.reqnum))
        while self.reqnum < MAX_SUB and len(self.q_wait) > 0:
            # peek at leftmost item in wait q (oldest item)
            f_obj = self.q_wait[0]
            logging.debug('{0} being examined.'.format(f_obj.filename))

            # If VTotal already has a report, then get/print it, and
            # then move the file to the "done" q

            if self.getrpt_before_scan_f:
                result = self.wk_getrpt(f_obj) 
                assert (result == 0 or result == 1 or result < 0)
                if result == 1:
                    f_obj = self.q_wait.popleft()
                    self.q_done.append(f_obj)
                    logging.debug('File {0} finished'.format(f_obj.filename))
                    continue

                # If have somehow gone over the limit for submissions, then stop
                elif result == -2:
                    self.reqnum = MAX_SUB
                    break

                # If RC = 0 then file is unknown to VTotal. Go and submit it.
                # If RC = -999 then http error
                elif result == 0 or result == -999:
                    pass
                elif result == -1:
                    logging.critical("API Key invalid")
                    sys.exit(300)
                else:
                    sys.exit(300)

            # otherwise submit file for scanning
            if self.reqnum < MAX_SUB:    
                logging.debug('{0} trying submit'.format(f_obj.filename))
                jsondata = self.myapi.scan_file(f_obj.filename)
                self.reqnum = self.reqnum + 1

                # If the submit was successful then put file on the in-process q
                # RCode "0" - not sure but think this means the file has
                # already been submitted but not finished scanning yet so
                # put file on the in-process q

                result = jsondata['result']
                assert (result == 0 or result == 1 or result < 0)
                if result  == 1:
                    f_obj = self.q_wait.popleft()
                    self.q_process.append(f_obj)
                    logging.info('{0} submitted for scan'.format(f_obj.filename))
                    continue
                # If have somehow gone over the limit for submissions,
                # then stop all submissions
                elif result == -2:
                    self.reqnum = MAX_SUB
                    break
                # If have RC=0 then file not in VTotal's dbase
                # yet. However have seen a test case 2010-11-14 where
                # a file kept giving 0 RC even though it had been
                # submitted interactively and had finished. A RC 0 on
                # a submit could mean that the file has already been
                # submitted and is still in their q or being
                # scanned. In any case, we don't take any chances on
                # having an endless loop, so just flag this as an
                # error situation and move on.
                elif result == 0:
                    f_obj = self.q_wait.popleft()
                    self.q_err.append(f_obj)
                    logging.warning('File {0} ret code 0 - not processed'.format(f_obj.filename))
                    continue
                # Http error or other unknown error
                elif result == -999:
                    continue
                elif result == -1:
                    logging.critical("API Key invalid")
                    sys.exit(300)
                else:
                    sys.exit(301)

        # Next try to retrieve results for in-process scans.  This
        # code assumes that if file a was submitted before file b,
        # then file a's results will come out before file b's. So we
        # start down the process q, oldest file first, looking to see
        # if the results are ready yet.

        logging.debug('Run the process queue. reqnum {0}'.format(self.reqnum))
        while len(self.q_process) > 0 and self.reqnum < MAX_SUB:
            # peek at first file submitted
            f_obj = self.q_process[0]
            logging.debug('{0} trying to get rpt'.format(f_obj.filename))

            # If report results are ready, then print them, then move the file to the "done" q
            result = self.wk_getrpt(f_obj)
            assert (result == 0 or result == 1 or result < 0)
            if result == 1:
                f_obj = self.q_process.popleft()
                self.q_done.append(f_obj)
                logging.debug('File {0} finished'.format(f_obj.filename))
                continue

            # If have somehow gone over the limit for submissions,
            # then stop all submissions
            elif result == -2:
                self.reqnum = MAX_SUB
                break

            # If have RC=0 so file is not in VTotal's dbase yet so
            # stop for now since the files behind this one in the q
            # are probably not ready either
            elif result == 0:
                # Sometimes files seem to get "stuck" with a RC = 0 so
                # give up after a reasonable delay
                f_obj.numattempts = f_obj.numattempts + 1
                if f_obj.numattempts > MAX_ATTEMPTS:
                    f_obj = self.q_process.popleft()
                    self.q_err.append(f_obj)
                    logging.warning('File {0} too many tries - not processed.'.format(f_obj.filename))
                    break
            # Http error or other unknown error
            elif result == -999:
                continue
            elif result == -1:
                logging.critical("API Key invalid")
                sys.exit(300)
            else:
                sys.exit(302)
    
    def wk_getrpt(self, f_obj):
        """ Check if report exists for this file object.
        """
        logging.info('{0} - check if report exists'.format(f_obj.filename))
        
        jsondata = self.myapi.get_report(f_obj.file_md5)
        self.reqnum = self.reqnum + 1

        # if results are ready then print them out
        if jsondata['result'] ==1:
            f_obj.get_results(jsondata)
            f_obj.prt_summary()
            return 1
        else:
            return jsondata['result']

    def wk_test(self):
        """ Return True if still some work to do
        """
        worktest = len(self.q_wait) > 0 or len(self.q_process) > 0
        logging.debug("wk_test: {0}".format(worktest))
        return worktest

    def wk_loop(self):
        """ Main worker loop to wait, then run the q's.
        """
        self.run_q()

        # Check if still something left to do and still not finished
        # submit interval

        while (len(self.q_process) > 0 or len(self.q_wait) > 0) and self.req_intvl < REQ_INTVL:
            logging.debug('Going to sleep.reqnum {0} intvl {1}'.format(
                self.reqnum, self.req_intvl))
            time.sleep(SLEEP_INTVL)
            self.req_intvl = self.req_intvl + SLEEP_INTVL
            if self.reqnum < MAX_SUB:
                self.run_q()

        # Are starting a new interval so reset the timer so that will
        # start submitting more requests again
            
        self.req_intvl = 0
        self.reqnum = 0

    def wk_done(self):
        """ Last things to do once all scans have completed.
        """
        logging.info("File scanning is completed.")
        # At the end, produce a full report for all files
        while len(self.q_done) > 0:
            f_obj = self.q_done.popleft()
            f_obj.prt_detail()
        while len(self.q_err) > 0:
            f_obj = self.q_err.popleft()
            logging.warning("{0} unknown ret code 0. File not processed.".format(f_obj.filename))

    def wk_stats(self):
        """ Print out 1-line summary of dequeue loadings
        """
        logging.info("# files: waiting: {0} being scanned: {1} done: {2} error: {3}".format(
              len(self.q_wait), len(self.q_process), len(self.q_done), len(self.q_err)))        
           

def main(argv=None):
    """ Main function in case this is called as a script from the cmd line.
    """
    global LEVELS

    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "ahrl:", ["noscan", "help", "loglevel=", "restart"])
        except getopt.error, msg:
             raise Usage(msg)

        # set defaults
        myloglevel = logging.INFO
        getrpt_before_scan_f = True
        restart_f = False

        # process options
        for o, a in opts:
            if o in ("-h", "--help"):
                print __doc__
                sys.exit(0)
            elif o in ("-l", "--loglevel"):
                myloglevel = LEVELS.get(a, logging.NOTSET)
                print "myloglevel ", myloglevel, logging.DEBUG, logging.NOTSET
                logging.basicConfig(level=myloglevel)
            elif o in ("-a", "--noscan"):
                getrpt_before_scan_f = False
            elif o in ("-r", "--restart"):
                restart_f = True
            else:
                logging.critical("Invalid option - logic error")
                sys.exit(100)

        logging.basicConfig(level=myloglevel)
        logging.debug("Debug log level set")

        # Do a restart if asked for
        pickle_filename = 'lgvtotal.pkl'
        if restart_f:
            logging.info("Doing a restart")
            try:
                pickle_fd = open(pickle_filename, 'rb')

                # Reload main work object and reinitialize API
                mywork = cPickle.load(pickle_fd)
                mywork.myapi = VTotApi()
                pickle_fd.close()
            except:
                logging.critical("Unable to open history file {0}".format(pickle_filename))
                raise
        else:
            # allocate new Worker object
            mywork = Worker(getrpt_before_scan_f)

            # load the wait q with the files to scan
            for arg in args:
                mywork.load_q(arg)

        # start main worker loop
        mywork.wk_stats()       # print out q stats

        while mywork.wk_test():    
            mywork.wk_loop()
            mywork.wk_stats()

            # preserve state at end of each interval
            
            pickle_fd = open(pickle_filename, 'wb')
            cPickle.dump(mywork, pickle_fd, -1)
            pickle_fd.close()

        # Finish up
        mywork.wk_done()


    except Usage, err:
        print >>sys.stderr, err.msg
        print >>sys.stderr, "for help use --help"
        return 2

if __name__ == "__main__":
    sys.exit(main())
