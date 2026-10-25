Cartwrite @VERSION@ for @PLATFORM@
====================================

Cartwrite packs a Nintendo Switch game, its update and its DLC into a single XCI file.
It can also extract a game, with its update applied, to a folder.

What's in this package
----------------------

@CONTENTS@

Setup
-----

Cartwrite needs a prod.keys file dumped from your own console. No keys are
included. Put prod.keys in one of these places:

  - %USERPROFILE%\.switch\prod.keys (Windows) or ~/.switch/prod.keys (Linux, macOS)
  - next to the Cartwrite program
  - in a folder called Keys next to the Cartwrite program

You can also choose the file in the app's Settings. The badge in the top right of
the window turns green when the keys are loaded.
@NOTES@
Using it
--------

1. Drag a game and its update (and any DLC) onto the window, or use Add files.
   To update an XCI you already have, drag in the XCI together with the new update.
2. Check the game card. Open Contents to see exactly what will be included.
3. Click Build. The XCI is saved next to the source files unless you pick an
   output folder at the bottom of the window.

Extracting to a folder
----------------------

Click Extract... on a game card, choose Game only or Game + DLC, pick a destination
and click Extract. The game goes to its own folder, holding exefs, romfs, control
and logo, with the update applied to romfs. DLC goes to a second folder next to
it, named "<game folder> DLC", as <title id>/romfs. Tools that read an extracted
game usually want the game folder, the one that holds exefs and romfs.

NSZ and XCZ input is decompressed to a temporary folder first, so it needs extra
free space while it runs.

Optional extras
---------------

Both are off by default and turned on in Settings, under Title database.

- Check for newer updates and missing DLC: compares your games with a community
  title database (blawar/titledb by default, or any URL or local file you choose).
- Show which region each release is from: adds US, EU, JP, Asia and KR flags
  to each game, from titledb's eShop lists (about 100 MB, downloaded once and
  refreshed monthly).

Command line
------------

  cartwrite-cli info  [--regions] <files or folders...>
  cartwrite-cli check [--titledb URL|FILE] [--refresh] <files or folders...>
  cartwrite-cli build [-o DIR] [--no-rsv] [--fat32] [--deltas] [--keys FILE] <files or folders...>
  cartwrite-cli extract [-o DIR] [--with-dlc] [--overwrite] [--keys FILE] <files or folders...>

More information
----------------

https://github.com/PlayingKarrde/Cartwrite

Cartwrite is inspired by NSC_Builder by julesontheroad. It is not affiliated with
NSC_Builder's author or with Nintendo. Licensed under GPL-3.0.
