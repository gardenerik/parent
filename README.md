# parent

A simple way to run process with limited resources.

## Usage

```
Options:
  -m, --memory INTEGER     Memory address space limit of the program in kB.
  -t, --cpu-time INTEGER   Limit the amount of CPU time the program can use in
                           milliseconds.
  -r, --real-time INTEGER  Limit the amount of real time the program can run
                           for in milliseconds.
  -f, --file-size INTEGER  Limit the size of files that the program can create
                           / modify in kB.
  -p, --processes INTEGER  Number of processes (or threads) the program can
                           use.
  -i, --stdin FILE         Redirect stdin from file.
  -o, --stdout FILE        Redirect stdout to file.
  -e, --stderr FILE        Redirect stderr to file.
  --stderr-to-stdout       Redirect stderr to stdout.
  -s, --stats FILENAME     File to write stats data to.
  --help                   Show this message and exit.
```
