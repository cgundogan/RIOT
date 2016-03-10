# DESVIRT integration into RIOT

You can find more information about desvirt at
https://github.com/des-testbed/desvirt

## Control DESVIRT via Make

### Variables

This Makefile introduces some additional variables:
 * TOPO
 * TOPO_SIZE
 * TOPO_TYPE

### Targets

It defines the following targets:
 * desvirt-topology
 * desvirt-define
 * desvirt-undefine
 * desvirt-list
 * desvirt-start
 * desvirt-stop
 * desvirt-clean
 * desvirt-distclean

#### desvirt-topology

This target creates a new topology file in RIOTBASE/dist/tools/desvirt/desvirt/.desvirt
It is necessary to supply the type and size of the new topology with `TOPO_TYPE` and `TOPO_SIZE`.
The make target will create the topology file with the name `$(TOPO_TYPE)$(TOPO_SIZE)`.
Examples:
```
TOPO_TYPE=line TOPO_SIZE=4 make desvirt-topology
TOPO_TYPE=grid TOPO_SIZE=9 make desvirt-topology
```
The names of the files will be: `line4` and `grid9`.

#### desvirt-define

This target defines a new topology. This must be done prior to starting desvirt.
```
TOPO=line4 make desvirt-define
```

#### desvirt-undefine

This target undefines a topology.
```
TOPO=line4 make desvirt-undefine
```

#### desvirt-list

This target lists all defined topologies.
```
make desvirt-list
```

#### desvirt-start

This target starts a new virtualization with the given topology name.
The topology must be defined beforehand.
```
TOPO=line4 make desvirt-start
```

#### desvirt-stop

This target stops a new virtualization with the given topology name.
The topology must be defined beforehand.
```
TOPO=line4 make desvirt-stop
```

#### desvirt-clean

This target resets the desvirt git-folder. All topologies will be deleted.
```
make desvirt-clean
```

#### desvirt-distclean

This target deletes the desvirt folder.
```
make desvirt-distclean
```
