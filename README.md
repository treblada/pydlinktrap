# pydlinktrap
Receive and process SmartConsole messages sent by D-Link switches.

Some D-Link switches have the feature to send
[traps](https://en.wikipedia.org/wiki/Trap_(computing)) about some events,
like link coming up/down, invalid logins and more.

Unfortunately, D-Link chose not to use the widely supported SNMP protocol,
rather they implemented something proprietary called *SmartConsole* which
sends UDP notifications on port 64514.

This project tries to make use of those message.

Once started it will listen to UDP port 64514 (by default) and invoke a
command for every received message. The details of the message are passed to
the invoked command via environment variables.

## Tested Devices
* DGS-1224T
* DGS-1100-08

If you have another device, you can help me by sending a dump of your
device's message. A dump will be created if you use the `--dump-payload` option.

It's likely that it also works with other devices, but there is no guarantee.
There is not even a guarantee, that it will work with the listed ones.

## Known Message Types
* (1001) System bootup
* (1002) WEB authenticate error from remote IP: xxx.xxx.xxx.xxx
* (3003) Port *X* copper link up
* (3004) Port *X* copper link down
* (5001) Firmware upgraded success
* (5002) Firmware upgraded failure
* (5005) Wrong file checksum causes firmware upgrade failure.

## How to install
The python executable comes with a command line help, which should explain the available
options.

The configuration file uses the long version of the CLI options as keywords.
An example is included in [dlinktrap.ini].
The program searches for the configuration file at `/etc/dlinktrap.ini`,
unless the `--config` option defines something else.

A *systemd* service file is included, see [dlinktrap.service]. On my ubuntu system it goes to
`/lib/systemd/system`.

## Caveats
No error is issued for invalid/unknown configuration keys in the configuration file.

## Credits
Thanks to [Ruslan Ohitin](https://github.com/ruslan-ohitin) for his project
[dlinktrapd](https://github.com/ruslan-ohitin/dlinktrapd) which in part inspired
this one.
