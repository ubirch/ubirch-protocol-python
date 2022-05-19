@page notPip Install from other source than pip 

<!-- These markdown files are supposed to be read by doxygen, 
a software for generating documentation. So don't wonder about the @page, 
@ref - or similar statements. Please refer as well to the 
official documentation at developer.ubirch.com -->

If you don't want to install from pip you can clone the git repository and install from there. 
If you want to install a specific branch of the repository, refer below.

## Install ubirch library locally from folder

Inside of the `ubirch/` repository folder run:
`$ pip install .`

## Install another branch than master

You can either clone new and specify the branch 

`$ git clone https://github.com/ubirch/ubirch-protocol-python.git --branch <other branch>`

Or if git branch doesn't return the branch you want to install, 
change it using `git checkout`
```
$ git branch
  ecdsa-examples
* master

$ git checkout <other branch>
Switched to a new branch 'ecdsa-examples'
```

Make sure correct branch is selected by running `$ git branch` again.

