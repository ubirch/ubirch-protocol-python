@page notMaster Install different branch than master

**Install ubirch-protocol from folder** `ubirch/`

If git branch doesn't return the branch you want to install, change it
```
$ git branch
  ecdsa-examples
* master
```

Either Switch branch:
```
$ git checkout <other branch>
Switched to a new branch 'ecdsa-examples'
```

OR clone new: 
```
$ git clone <this repo> --branch <other branch>
```

Make sure correct branch is selected with `$ git branch`

Install ubirch-protocol from this branch: 
```
$ pip install .
```