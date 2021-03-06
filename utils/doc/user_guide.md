This user guide describe filter information for UTIL pan-os-php type=rule
===

pan-os-php type=rule
---

pan-os-php type=rule filter description for SRC and DST
[ghost/TMP objects are IP-address directly defined in Rules]

- has
    - based on object names (not values)
    - the filter will first check whether the object even exists (ignores ghost/TMP objects)
    - the filter will return partial AND full matches
    - this filter does not match "any"
    - example: 
        - filter is 8.8.8.8 and the rule destination is 8.8.8.8 and 4.4.4.4, it will match
        - filter is 8.8.8.8 and the rule destination is 8.8.8.8, it will match

- has.from.query

- has.only 
    - based on object names (not values)
    - the filter will first check whether the object even exists (ignores ghost/TMP objects)
    - the filter will return only full matches
    - this filter does not match "any"
    - example:
        - filter is 8.8.8.8 and the rule destination is 8.8.8.8 and 4.4.4.4, it will not match
        - filter is 8.8.8.8 and the rule destination is 8.8.8.8, it will match

- has.recursive

- has.recursive.from.query

- has.recursive.regex

- included-in.full

- included-in.full.or.partial

- included-in.partial

- includes.full

- includes.full.or.partial

- includes.partial

- is.any

- is.fully.included.in.list 
    - this search is based on object values (including ghost/TMP objects)
    - this will search inside groups, nested groups and object values
    - the filter will return only full matches
    - this filter does not match "any"
    - in case of subnets, the summary of all the destination members must "fit" within the searched subnet
    - example:
        - filter is 8.8.8.8 and the rule destination is 8.8.8.8 and 4.4.4.4, it will not match 
        - filter is 8.8.8.8 and the rule destination is 8.8.8.8, it will match
        - filter is 10.11.11.10/30 and the rule destination is 10.11.11.0/24, it will not match
        - filter is 10.11.11.10/30 and the rule destination is 10.11.11.11, it will not match
        - filter is 10.11.11.0/24 and the rule destination is 10.11.11.0/24, it will match
        - filter is 10.11.11.0/24 and the rule destination is 10.11.11.0/24 and 10.11.11.0/16, it will not match
        - filter is 10.0.0.0/8 and the rule destination is 10.11.11.0/24 and 10.11.11.0/16, it will match
        - filter is 10.0.0.0/8 and the rule destination is 10.11.11.0/24 and 10.11.11.0/16 and 1.1.1.1/32, it will not match

- is.negated

- is.partially.included.in.list
    - this search is based on object values (including ghost/TMP objects)
    - this will search inside groups, nested groups and object values
    - the filter will return only partial matches
    - this filter does not match "any"
    - in case of subnets, the summary of all the destination members must contain more addresses than the filter, but the filter must match at least some of them 
    - example:
        - filter is 8.8.8.8 and the rule destination is 8.8.8.8 and 4.4.4.4, it will match
        - filter is 8.8.8.8 and the rule destination is 8.8.8.8, it will not match
        - filter is 10.11.11.10/30 and the rule destination is 10.11.11.0/24, it will match
        - filter is 10.11.11.10/30 and the rule destination is 10.11.11.11, it will not match
        - filter is 10.11.11.0/24 and the rule destination is 10.11.11.0/24, it will not match
        - filter is 10.11.11.0/24 and the rule destination is 10.11.11.0/24 and 10.11.11.0/16, it will match
        - filter is 10.0.0.0/8 and the rule destination is 10.11.11.0/24 and 10.11.11.0/16, it will not match
        - filter is 10.0.0.0/8 and the rule destination is 10.11.11.0/24 and 10.11.11.0/16 and 1.1.1.1/32, it will match

- is.partially.or.fully.included.in.list 
    - this search is based on object values (including ghost/TMP objects)
    - this will search inside groups, nested groups and object values
    - the filter will return partial AND full matches
    - this filter does not match "any"
    - example:
        - filter is 8.8.8.8 and the rule destination is 8.8.8.8 and 4.4.4.4, it will match
        - filter is 8.8.8.8 and the rule destination is 8.8.8.8, it will match
        - filter is 10.11.11.10/30 and the rule destination is 10.11.11.11, it will match
        - filter is 10.11.11.10/30 and the rule destination is 10.11.11.0/24, it will match
        - filter is 10.11.11.0/24 and the rule destination is 10.11.11.0/24, it will match
        - filter is 10.11.11.0/24 and the rule destination is 10.11.11.0/24 and 10.11.11.0/16, it will match
        - filter is 10.0.0.0/8 and the rule destination is 10.11.11.0/24 and 10.11.11.0/16, it will match
        - filter is 10.0.0.0/8 and the rule destination is 10.11.11.0/24 and 10.11.11.0/16 and 1.1.1.1/32, it will match
