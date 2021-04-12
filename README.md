# nso-param-search
A tool for searching for param hashes in Smash Ultimate NSO binaries

Input: an NSO file to search and a ParamLabels.csv

Output: GHIDRA Jython code to apply the labels to the given version of the binary

## Usage

```
nso-param-search 0.1.0

USAGE:
    nso-param-search <nso-file> <param-labels>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <nso-file>
    <param-labels>
```

## Example Output

![](https://cdn.discordapp.com/attachments/376971848555954187/830957228956581888/unknown.png)
