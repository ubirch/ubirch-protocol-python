
# About auto-generating a documentation with Doxygen

### First, Install [Doxygen](https://www.doxygen.nl/index.html)
- I had Issues with installation from source, dependency problems 
- So just install with brew: (Made with version 1.9.3)

`brew install doxygen@1.9.3`

### Run
inside of `documentation/` run

`doxygen Doxyfile`

### Files

The `Doxyfile` contains all configuration options. 
It uses the `layout/` and the `static/` directories for layout and styling.

Inside of the `pages/` directory you'll find Markdown files that Doxygen makes available in the generated doc.
These markdown files are very similar to normal markdown but consider these differences:

## Linking
### Internal Links to classes or functions in Markdown with
```
[API](@ref ubirch.ubirch_api.API)

[deregister_identity()](@ref ubirch.ubirch_api.API::deregister_identity)
```

### Internal Links inside Markdown file to Markdown headings/titles with
```
[gettingStarted](#start)
[Install](#inst)


@section start gettingStarted
@subsection inst Installation
```
### Links to other markdown files
By `@page` attribute

In One File 
`@page examples Example Implementations`

In other file 
`[Examples](@ref examples)`

______________________________

## Comments
Write a comment using standard HTML syntax
```
<!--
This is a comment
-->
```


### BUGS!
A Comment in a Markdown File isn't allowed to be on the first line. Otherwise a weirdly named second file is generated

### Ignore these warnings
```warning: unable to resolve reference to 'data-format' for \ref command```

They are caused by Doxygen handling links inside of files differently (Like shown above)

Since with normal Markdown it works like this:
```
[Install](#installation)

## Installation
```