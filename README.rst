extensible gacha game headless client/swiss-knife library

many mobile gacha games, especially those from the same company, have
similar protocols and engines. the idea is to modularly implement the
common things for each family of gacha game engine/api and then implement
the game-specific details on top. ideally, once enough common stuff is
implemented, you would be able to quickly implement a client for any
gacha game without having to think about the protocol too much or having
to rewrite similar boilerplate for each game

I chose python because it allows for very quick prototyping, and since
these games get updated and change all the time, being able to adapt to
changes and taping together libraries quickly is more important than neat
code

setting up an environment
===========
at the moment, the code relies on python 3.7+. on windows, you would
download the installer from the python website. on linux, most distros ship
a recent enough version in their packages, but if they don't you can use
pyenv to compile it from source:

.. code-block:: sh

    curl https://pyenv.run | bash
    pyenv install -v 3.7.5
    pyenv global 3.7.5

not sure which dependencies pyenv wants to build python as I already had
everything

now you can manually install the module with pip and run it

.. code-block:: sh

    python3 -m pip install .
    python3 -m gachanator --log all

of course, you can also import this as a module and build your own code
on top of it

tests can be run with

.. code-block:: sh

    python3 -m test_gachanator

built-in plugins
===========
- captain tsubasa dream team (global/english version)
- (work in progress) love live school idol festival all stars (jp)

writing plugins
===========
add your .py file to the plugins directory, implement the `Plugin`
interface and make sure to define `__plugin__` to your client subclass.
see existing plugins as an example

threading model is purposefully simple (but inefficient). each plugin
provides a list of tasks, each task is executed in its own thread, which
with python is actually a forked child process. therefore it's recommended
to run this on linux or other unix-like OSes that have very optimized
forking

this simple threading models allows you to write plugin logic as if it was
synchronous without thinking too much about concurrency

all database operations are serialized into a queue that is processed by
a single database worker thread to avoid lock contention

I haven't had time to set up proper documentation, but you can look at the
[captain tsubasa dream team plugin](https://github.com/Francesco149/gachanator/plugins/dteam_en.py)
for an example of a fully working client

also, you can run `pydoc gachanator.gachanator` for a complete reference of
all classes and functions

what it can do
===========
- download apk/xapk's from qooapp and apkpure
- read arbitrarily nested files inside apk's, also works with nested apks
- extract package signature hashes from `/META-INF/CERT.RSA`
- convert .net xml pub keys to pem
- implements klab's AssetStateV2, used in sifas, dream team and probably
  others
- parse strings from unity's il2cpp `global-metadata.dat` and extract
  things like the endpoint, startup key and other things you would have
  to manually update
- already implements generic updater logic through the `Downloader` and
  `Plugin` interfaces, you only need to fill in the game-specific stuff
  which usually amounts to the game's name and package name for the apkpure
  downloader and extracting strings from the apk
- get real push notificaton tokens using my `push_receiver` library and
  potentially read push notifications as well

coding style
===========
I want to make it as easy as possible to set up an environment and start
hacking, so minimize native dependencies or keep them to ffi like the
crypto library I'm using. sqlite3 is unavoidable but everything else should
ideally be pure python

unlike languages with braces, it's really hard to get a good consistent
feel with python formatting, so i use autopep8 to autoformat code. use the
included `fmt.sh` script to format code
