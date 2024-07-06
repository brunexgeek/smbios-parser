# smbios-parser

Small C99 and C++98 library to parse SMBIOS information.

The [SMBIOS](https://www.dmtf.org/standards/smbios) (System Management BIOS) is a standard specification that specifies how system vendors present management information about their products. It extends the BIOS interface on Intel architecture systems and allow operating systems (or programs) to retrieve information about the hardware without needing to probe it directly.

This library is a small and standalone implementation of the specification for C and C++ applications. You can also use the shared library with any C-compatible programming language (i.e. Python, Go, Java).

## Usage

The library can be used in C and C++ applications in the following ways:

*   As a static or shared library;
*   Copying the files `smbios.h` and `smbios.c` into your project.

Once selected the preferred integration method, the library can be used as follows:

```c
#include <smbios.h>

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    // Get SMBIOS information using a custom function.
    // An example in C for Windows and Linux can be found
    // in 'smbios_decode.c'.
    const uint8_t *data = NULL;
    size_t size = 0;
    load_smbios_data(&data, &size);

    // initialize the parser (the desired SMBIOS version is 3.0)
    struct ParserContext context;
    if (smbios_init(&context, data, size, SMBIOS_3_0) != SMBERR_OK)
        return 1;

    // iterate over the SMBIOS entries
    const struct Entry *entry = NULL;
    while (smbios_parse(&context, &entry) == SMBERR_OK)
    {
        // do something with the current entry
    }

    return 0;
}
```

The pointer to the current SMBIOS entry is stored in the variable specified as the second parameter of the `smbios_next` function. The entry is defined by the structure `Entry` and some of its most important fields are:

* **type**: Entry type, as defined in the SMBIOS specification;
* **handle**: Entry handle, a unique 16-bit number in the range 0 to 0FFFEh (for version 2.0) or 0 to 0FEFFh (for version 2.1 and later);
* **data**: Union with the actual formatted data of the entry for each supported type. For example, the `ProcessorInfo` entry is stored in the `data.processor` field.
* **strings**: Pointer to the start of the string table;
* **string_count**: Number of strings in the string table.

The library do not make heap allocations: everything is done in-place using the provided SMBIOS buffer and the context.

## API

The following functions are available. If you're using the library in a C++ code, the functions will be defined in the `smbios` namespace.

### smbios_initialize

`int smbios_initialize(struct ParserContext *context, const uint8_t *data, size_t size, enum SpecVersion version )`

Initialize the SMBIOS parser.

If the actual version of the SMBIOS data is smaller than the value of the parameter `version`, the parser will use the version of the SMBIOS data. Fields related to SMBIOS versions not selected will be left blank. Valid values are the ones defined in the enumeration `SpecVersion`.

* **context**: Parser context.
* **data**: SMBIOS data.
* **size**: Size of the SMBIOS data.
* **version**: Preferred SMBIOS version.

The function returns SMBERR_OK on success or a negative error code.

### smbios_next

`int smbios_next(struct ParserContext *context, const struct Entry **entry)`

Get the next SMBIOS entry.

Calling this function invalidates any previously returned entry.

* **context**: Parser context.
* **entry**: Pointer to the entry.

The function returns SMBERR_OK on success or a negative error code.

### smbios_reset

`int smbios_reset(struct ParserContext *context)`

Reset the SMBIOS parser and let it start from the beginning.

If the parser failed (e.g. invalid SMBIOS data), calling this function will fail too.

* **context**: Parser context.

The function returns SMBERR_OK on success or a negative error code.

### smbios_get_version

`int smbios_get_version(struct ParserContext *context, enum SpecVersion *selected, enum SpecVersion *original)`

Returns the selected and/or the original SMBIOS versions.

* **context**: Parser context.
* **selected**: `(optional)` Selected version used to parse the SMBIOS data.
* **original**: `(optional)` Version of the SMBIOS data.

The function returns SMBERR_OK on success or a negative error code.

### smbios_get_string

`const char *smbios_get_string( const struct Entry *entry, int index )`

Returns a string from the SMBIOS entry.

Fields in the entry that reference a string are automatically set with the corresponding string pointer. However, some entry types have an arbitrary number of strings not pointed by entry fields (e.g. the `OEMStrings` entry type). In this case, you can use this function to retrieve them.

This is a utility function to retrieve a string from the SMBIOS entry. The function will iterate over the strings in the SMBIOS entry and return the string with the given index, starting from 1. If the index is out of range, the function will return `NULL`.

If you want to avoid the overhead of the iteration for each call, you can access the string table directly. The start of the string table is set in the field `strings` of the entry. Each string is terminated with a null (00h) byte and the table is terminated with an additional null (00h) byte. The amount of strings is given in the field `string_count` of the entry.

* **entry**: SMBIOS entry.
* **index**: Index of the string, starting from 1.

The function returns the string associated with the given index or `NULL` in case of error.

## License

The library and the compiler are distributed under [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).