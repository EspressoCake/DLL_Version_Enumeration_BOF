# DLL Image Resource Version Enumeration BOF

## What is this?
- This is a `Cobalt Strike` `BOF` file (a mildly massaged port of [@N4k3dTurtl3's](https://twitter.com/N4k3dTurtl3) existing PoC , meant to use ascertain information regarded imported `DLLs` (via the `ENTRY_RESOURCE`) within current process that your beacon associated with.


## What problem are you trying to solve?
1.  Given my current projects regarding `DLLs`, this is yet another blindspot I wanted to address after seeing [@N4k3dTurtl3's](https://twitter.com/N4k3dTurtl3) work.
2.  I wanted to support both `32-bit` AND `64-bit` `Beacon` sessions.
3.  I wanted to have verbose or minified output, given an operator's desire
4.  I wanted to keep the original design of [@N4k3dTurtl3's](https://twitter.com/N4k3dTurtl3) intact; minimal API calls.
	1.  This is solved this by rolling our own from `grok`ed or `cribbed` implementations elsewhere.

## How do I build this?
1. In this case, you have two options:
	1. Use the existing, compiled object file, located in the `dist` directory (AKA proceed to major step two)
    2. Compile from source via the `Makefile`
        1. `cd src`
        2. `make clean`
        3. `make`
2. Load the `Aggressor` file, in the `Script Manager`, located in the `dist` directory

## How do I use this?
- From a given `Beacon`:
![](https://i.ibb.co/NmbygW4/Help-Text.png)
##
## Any known downsides?
- We're still using the `Win32` API and `Dynamic Function Resolution`.  This is for you to determine as far as "risk", though this is limited to a single comparison function (`stricmp`).
- You may attempt to incur a privileged action without sufficient requisite permissions.  I can't keep you from burning your hand.

##
## What does the output look like?
#### All known `DLL`s associated with the process
![](https://i.ibb.co/2MJWkx2/base-non-verbose.png)
#### Verbose output of the aforementioned
![](https://i.ibb.co/jRg2FKR/verbose-all.png)
#### Verbose output of the aforementioned with `needle`
![](https://i.ibb.co/bKqMrTN/Verbose-Needle.png)
