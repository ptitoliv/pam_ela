# pam_ela
pam_ela is a PAM module which does Ethernet Link Allocation (ELA)

# Introduction
pam_ela is a PAM session module which creates a dedicated network namespace for a logged user on session creation. On session opening, pam_ela executes the following operations :
 * Creates a dedicated network namespace
 * Creates a VETH pair
 * Attaches a VETH peer on the namespace
 * Attaches the other VETH peer on the main network namespace and enslaves it on the br0 bridge
  
# Compilation

``` 
make && make install 
```

# Installation

Edit your pam target and add the following line on session block

```
session    optional     pam_ela.so
```

# Disclaimer
pam_ela is a simple PoC written by a guy who is a terrible C developper. So just use it for test purpose. I won't guarntee that the code is safe and/or secure.
