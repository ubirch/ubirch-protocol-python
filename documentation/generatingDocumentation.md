
# About auto-generating a documentation with Doxygen
The `Doxyfile` contains all configuration options. 
It uses the `layout/` and the `static/` directories for layout and styling.

Inside of the `pages/` directory you'll find Markdown files that Doxygen makes available in the generated doc.
These markdown files are very similar to normal markdown but consider these differences:

### Internal Links to classes or functions in Markdown with
- [API](@ref ubirch.ubirch_api.API)
- [deregister_identity()](@ref ubirch.ubirch_api.API::deregister_identity)
```
[API](@ref ubirch.ubirch_api.API)

[deregister_identity()](@ref ubirch.ubirch_api.API::deregister_identity)
```

### Internal Links inside Markdown file to Markdown headings/titles with
- [gettingStarted](#start)
- [Install](#inst)

```
[gettingStarted](#start)
[Install](#inst)


@section start gettingStarted
@subsection inst Installation
```

### Ignore these warnings 
```statingwarning: unable to resolve reference to 'data-format' for \ref command```

They are caused by Doxygen handling links inside of files differently (Like shown above)

Since with normal Markdown works like this:

[Install](#installation)

```
[Install](#installation)

## Installation
```




