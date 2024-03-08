# lco-sync
Download data from the LCO archive.  Maybe run once, or set to periodically check for new files.

## Requires
* astropy
* requests

I use pip for my dependencies: `pip install astropy requests`

## Usage

Create a configuration file in your `.config` directory:
```bash
cat > ~/.config/lco-sync.config<<EOF
{
  "username": "your@username",
  "password": "your-password"
}
EOF
chmod 600 ~/.config/lco-sync.config
```

Get help: `python3 sync.py --help`

Get all data for your project since 2020-01-01: `python3 sync.py proposal_id --since=2020-01-01`

One-time-mode, only sync data for your favorite object: `python3 sync.py proposal_id --since=2020-01-01 --object=2P`

Daemon-mode, periodically check for new files: `python3 sync.py proposal_id`

## Notes
It may not be the best code, but works!
