# Licensed under a MIT style license - see LICENSE
"""sync - Sync LCO data with local archive.

Thanks to Nestor Espinoza's lcogtDD for an example on syncing with LCO.

"""

import io
import os
import sys
import json
import time
import logging
import argparse
import requests
from astropy.table import Table
from astropy.time import Time
import astropy.units as u


class AuthorizationError(Exception):
    pass


class ArchiveFileAlreadyExists(Exception):
    pass


class Sync:
    """Sync observations with LCO.

    Parameters
    ----------
    proposal : string
        LCO archive proposal ID.

    object : string, optional
        Only sync data matching this object.

    config_filg : string, optional
        Configuration file containing username and password.

    post_sync : string, optional
        Run this executable after downloading new files.

    login : bool, optional
        Set to ``False`` and only public data will be searched.

    verbose : bool, optional
        Send info messages to the console.

    debug : bool, optional
        Enable any debuging parameters.

    """

    def __init__(self, proposal, object=None,
                 config_file='~/.config/lco-sync.config',
                 post_sync=None, login=True, verbose=False,
                 debug=False):
        self.download_path = './'
        self.proposal = proposal
        self.object = object
        self.post_sync = post_sync
        self.login = login
        self.verbose = verbose
        self.debug = debug

        self._logging(True)

        with open(os.path.expanduser(config_file)) as inf:
            self.config = json.load(inf)

        self.request_delay = 1 * u.s
        self.last_request = Time.now() - self.request_delay
        self.last_download = None

        # get http authorization token from LCO
        if self.login:
            self._get_auth_token()
        else:
            self.auth = None
            self.logger.info('Not logged in, only searching public data.')

    def _logging(self, log_to_file):
        logger = logging.Logger('lco-sync')
        log_level = logging.DEBUG if self.debug else logging.INFO

        # This test allows logging to work when it is run multiple times
        # from ipython
        if len(logger.handlers) == 0:
            formatter = logging.Formatter('%(levelname)s: %(message)s')

            console = logging.StreamHandler(sys.stdout)
            console.setFormatter(formatter)
            console.setLevel(log_level if self.verbose else logging.WARNING)
            logger.addHandler(console)

            if log_to_file:
                fn = 'lco-sync.log'
            else:
                fn = '/dev/null'

            logfile = logging.FileHandler(fn)
            logfile.setFormatter(formatter)
            logfile.setLevel(log_level)
            logger.addHandler(logfile)

        logger.info('#' * 70)
        logger.info(Time.now().iso + 'Z')
        logger.info('Command line: ' + ' '.join(sys.argv[1:]))
        for handler in logger.handlers:
            if hasattr(handler, 'baseFilename'):
                logger.info('Logging to ' + handler.baseFilename)

        self.logger = logger

    def log_table(self, tab):
        with io.StringIO() as s:
            tab.write(s, format='ascii.fixed_width_two_line')
            s.seek(0)
            self.logger.info("\n" + s.read(-1))

    def _download_frame(self, meta):
        """Download a frame described by metadata from an LCO frame payload.

        Target location:
          download_path/e(rlevel)/UTC_date/filename

        If the file already exists, the download is skipped.

        Raises
        ------
        ArchiveFileAlreadyExists

        """

        # first, verify target path and create subdirectories if needed
        d = self.download_path
        for tail in ('e{}'.format(meta['RLEVEL']),
                     meta['DATE_OBS'][:10].replace('-', '')):
            d = os.sep.join([d, tail])
            if os.path.exists(d):
                assert os.path.isdir(d), \
                    '{} exists, but is not a directory'.format(d)
            else:
                os.mkdir(d)

        # archive file name format:
        # (site)(tel)-(instr)-YYYYMMDD-(frame)-(type)(red.level).fits
        filename = os.sep.join([d, meta['filename']])

        if os.path.exists(filename):
            self.logger.debug(
                '{} already exists, skipping download.'.format(filename))
            raise ArchiveFileAlreadyExists(filename)
        else:
            self.logger.info('Downloading to {}.'.format(filename))
            with open(filename, 'wb') as outf:
                outf.write(requests.get(meta['url']).content)

    def _get_auth_token(self):
        data = {
            'username': self.config['username'],
            'password': self.config['password']
        }
        r = requests.post('https://archive-api.lco.global/api-token-auth/',
                          data=data).json()
        token = r.get('token')
        if token is None:
            raise AuthorizationError('Authorization token not returned.')
        self.auth = {'Authorization': 'Token ' + token}
        self.logger.info('Obtained authorization token.')

    def continuous_sync(self, rlevels=[91], download=True):
        """Continuously check for new data.

        Parameters
        ----------
        rlevels : list of int, optional
          Reduction levels to check.
        download : bool, optional
          Download flag.

        """
        
        window = 1 * u.day  # search window
        cadence = 2 * u.hr  # search cadence
        last_sync = Time('2000-01-01')
        self.logger.info(
            '{} Entering continuous sync mode, checking LCO archive every {} with a {}-wide search window.'.format(Time.now().iso, cadence, window))

        try:
            while True:
                now = Time.now()
                if (now - last_sync) > cadence:
                    self.logger.info(Time.now().iso +
                                     ' Sync with LCO archive.')
                    new_files = self.sync(now - window, rlevels=rlevels,
                                          download=download)
                    last_sync = Time.now()
                else:
                    dt = int((now - last_sync).sec)
                    sleep = int(cadence.to(u.s).value) - dt + 2
                    self.logger.debug(
                        'Last sync: {} UT ({} s ago).  Sleep {} s.'.format(now.iso[:16], dt, sleep))
                    time.sleep(sleep)
                    self.logger.debug('Awake!')
        except KeyboardInterrupt:
            self.logger.info('Caught interrupt signal.  Shutdown.')

    def request(self, url, query={}):
        """Send HTTP request and return the output.

        Limits the overall number of requests to slow down any runaway
        code and prevent from exceeding the request limit.

        Parameters
        ----------
        url : string
          The URL.
        param : dict, optional
          The HTTP get parameters.

        """

        while (Time.now() - self.last_request) < self.request_delay:
            time.sleep(1)

        self.logger.info('Request: {}, {}'.format(url, query))
        response = requests.get(url, params=query, headers=self.auth)
        self.logger.debug(response.url)

        data = response.json()
        return data

    def _summarize_payload(self, payload):
        """Summarize payload as a table."""

        tab = Table(names=('filename', 'date_obs', 'object', 'filter', 'exptime'),
                    dtype=('U64', 'U32', 'U32', 'U16', float))
        for meta in payload:
            tab.add_row((meta['filename'], meta['OBJECT'], meta['DATE_OBS'],
                         meta['FILTER'], float(meta['EXPTIME'])))
        return tab

    def sync(self, start=None, end=None, rlevels=[91], download=True):
        """Request frames list from LCO and download, if needed.

        Only whole days are checked.

        Parameters
        ----------
        start : Time, optional
          Check for frames since `start`.  Default is now - 24 hr.
        end : Time, optional
          Check for frames no later than `end`.
        rlevels : list of int, optional
          Which reduction levels to check.
        download : bool, optional
          Flag to download data.

        Return
        ------
        new_files : bool
          `True` if new files were downloaded.

        """

        if start is None:
            start = Time.now() - 24 * u.hr

        new_files = False
        for rlevel in rlevels:
            query = {
                'PROPID': self.proposal,
                'limit': 50,
                'RLEVEL': rlevel,
                'start': start.iso[:10],
                'format': 'json'
            }
            if self.object is not None:
                query['OBJECT'] = self.object

            if end is not None:
                query['end'] = end.iso[:10]

            data = self.request('https://archive-api.lco.global/frames/',
                                query=query)
            self.logger.debug('{} Found {} frames with reduction level {}.'.format(
                Time.now().iso, data['count'], rlevel))

            dl_count = 0
            skip_count = 0
            while True:  # loop over all payload sets
                payload = data['results']

                if data['count'] > 0:
                    tab = self._summarize_payload(payload)
                    if download:
                        downloaded = []
                        for i, meta in enumerate(payload):
                            try:
                                self._download_frame(meta)
                                dl_count += 1
                                downloaded.append(i)
                            except ArchiveFileAlreadyExists:
                                skip_count += 1
                                pass
                        if len(downloaded) > 0:
                            #self.log_table(tab[downloaded])
                            tab[downloaded].pprint_all()
                    else:
                        self.log_table(tab)
                        tab.pprint_all()

                if data['next'] is not None:
                    # get next payload set
                    data = self.request(data['next'])
                else:
                    break  # end while loop

            self.logger.info('{} Downloaded {} files, {} skipped.'.format(
                Time.now().iso, dl_count, skip_count))

            if dl_count > 0 and self.post_sync is not None:
                os.system(self.post_sync)

            new_files += dl_count > 0

        return new_files


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('proposal',
                        help='LCO proposal ID')
    parser.add_argument('--since', type=Time,
                        help='find data in the archive since this date')
    parser.add_argument('--object',
                        help='only sync data matching this object')
    parser.add_argument('--continuous', action='store_true',
                        help='run in continuous sync mode')
    parser.add_argument('--post-sync',
                        help='run this executable after downloading new files')
    parser.add_argument('--no-login', dest='login', action='store_false',
                        help=('do not login to the data archive, limiting '
                              'search to public data'))
    parser.add_argument('--debug', action='store_true',
                        help='enable debugging messages')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show more messages on the console')
    args = parser.parse_args()

    sync = Sync(args.proposal, object=args.object, post_sync=args.post_sync,
                login=args.login, debug=args.debug, verbose=args.verbose)
    try:
        if args.continuous:
            sync.continuous_sync()
        else:
            sync.sync(args.since)
    except Exception as e:
        sync.logger.error(str(e))
        if args.verbose:
            raise(e)
