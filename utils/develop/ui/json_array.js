
var subjectObject =
    {
        "address": {
            "action": {
                "add-member": {
                    "name": "add-member",
                    "MainFunction": {},
                    "args": {
                        "addressobjectname": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "addobjectwhereused": {
                    "name": "addObjectWhereUsed",
                    "MainFunction": {},
                    "args": {
                        "objectName": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "skipNatRules": {
                            "type": "bool",
                            "default": false
                        }
                    }
                },
                "addtogroup": {
                    "name": "AddToGroup",
                    "MainFunction": {},
                    "args": {
                        "addressgroupname": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "devicegroupname": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "please define a DeviceGroup name for Panorama config or vsys name for Firewall config.\n"
                        }
                    }
                },
                "decommission": {
                    "name": "decommission",
                    "MainFunction": {},
                    "args": {
                        "file": {
                            "type": "string",
                            "default": "false"
                        }
                    }
                },
                "delete": {
                    "name": "delete",
                    "MainFunction": {}
                },
                "delete-force": {
                    "name": "delete-Force",
                    "MainFunction": {}
                },
                "description-append": {
                    "name": "description-Append",
                    "MainFunction": {},
                    "args": {
                        "stringFormula": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n"
                        }
                    },
                    "help": ""
                },
                "description-delete": {
                    "name": "description-Delete",
                    "MainFunction": {}
                },
                "display": {
                    "name": "display",
                    "MainFunction": {}
                },
                "display-nat-usage": {
                    "name": "display-NAT-usage",
                    "MainFunction": {}
                },
                "displayreferences": {
                    "name": "displayReferences",
                    "MainFunction": {}
                },
                "exporttoexcel": {
                    "name": "exportToExcel",
                    "MainFunction": {},
                    "GlobalInitFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "filename": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "additionalFields": {
                            "type": "pipeSeparatedList",
                            "subtype": "string",
                            "default": "*NONE*",
                            "choices": [
                                "WhereUsed",
                                "UsedInLocation",
                                "ResolveIP",
                                "NestedMembers"
                            ],
                            "help": "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n  - NestedMembers: lists all members, even the ones that may be included in nested groups\n  - ResolveIP\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n  - WhereUsed : list places where object is used (rules, groups ...)\n"
                        }
                    }
                },
                "move": {
                    "name": "move",
                    "MainFunction": {},
                    "args": {
                        "location": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "mode": {
                            "type": "string",
                            "default": "skipIfConflict",
                            "choices": [
                                "skipIfConflict",
                                "removeIfMatch",
                                "removeIfNumericalMatch"
                            ]
                        }
                    }
                },
                "name-addprefix": {
                    "name": "name-addPrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-addsuffix": {
                    "name": "name-addSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removeprefix": {
                    "name": "name-removePrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removesuffix": {
                    "name": "name-removeSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-rename": {
                    "name": "name-Rename",
                    "MainFunction": {},
                    "args": {
                        "stringFormula": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n  - $$netmask$$ : netmask\n  - $$netmask.blank32$$ : netmask or nothing if 32\n  - $$reverse-dns$$ : value truncated of netmask if any\n  - $$value$$ : value of the object\n  - $$value.no-netmask$$ : value truncated of netmask if any\n"
                        }
                    },
                    "help": ""
                },
                "name-replace-character": {
                    "name": "name-Replace-Character",
                    "MainFunction": {},
                    "args": {
                        "search": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "replace": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    },
                    "help": ""
                },
                "removewhereused": {
                    "name": "removeWhereUsed",
                    "MainFunction": {},
                    "args": {
                        "actionIfLastMemberInRule": {
                            "type": "string",
                            "default": "delete",
                            "choices": [
                                "delete",
                                "disable",
                                "setAny"
                            ]
                        }
                    }
                },
                "replace-ip-by-mt-like-object": {
                    "name": "replace-IP-by-MT-like-Object",
                    "MainFunction": {}
                },
                "replace-object-by-ip": {
                    "name": "replace-Object-by-IP",
                    "MainFunction": {}
                },
                "replacebymembersanddelete": {
                    "name": "replaceByMembersAndDelete",
                    "MainFunction": {},
                    "args": {
                        "keepgroupname": {
                            "type": "string",
                            "default": "*nodefault*",
                            "choices": [
                                "tag",
                                "description"
                            ],
                            "help": "- replaceByMembersAndDelete:tag -> create Tag with name from AddressGroup name and add to the object\n- replaceByMembersAndDelete:description -> create Tag with name from AddressGroup name and add to the object\n"
                        }
                    }
                },
                "replacewithobject": {
                    "name": "replaceWithObject",
                    "MainFunction": {},
                    "args": {
                        "objectName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "showip4mapping": {
                    "name": "showIP4Mapping",
                    "MainFunction": {}
                },
                "split-large-address-groups": {
                    "name": "split-large-address-groups",
                    "MainFunction": {},
                    "args": {
                        "largeGroupsCount": {
                            "type": "string",
                            "default": "2490"
                        }
                    }
                },
                "tag-add": {
                    "name": "tag-Add",
                    "section": "tag",
                    "MainFunction": {},
                    "args": {
                        "tagName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "tag-add-force": {
                    "name": "tag-Add-Force",
                    "section": "tag",
                    "MainFunction": {},
                    "args": {
                        "tagName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "tag-remove": {
                    "name": "tag-Remove",
                    "section": "tag",
                    "MainFunction": {},
                    "args": {
                        "tagName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "tag-remove-all": {
                    "name": "tag-Remove-All",
                    "section": "tag",
                    "MainFunction": {}
                },
                "tag-remove-regex": {
                    "name": "tag-Remove-Regex",
                    "section": "tag",
                    "MainFunction": {},
                    "args": {
                        "regex": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "value-host-object-add-netmask-m32": {
                    "name": "value-host-object-add-netmask-m32",
                    "MainFunction": {}
                },
                "value-set-ip-for-fqdn": {
                    "name": "value-set-ip-for-fqdn",
                    "MainFunction": {}
                },
                "value-set-reverse-dns": {
                    "name": "value-set-reverse-dns",
                    "MainFunction": {}
                },
                "z_beta_summarize": {
                    "name": "z_BETA_summarize",
                    "MainFunction": {}
                }
            },
            "filter": {
                "description": {
                    "operators": {
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/test\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.empty": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "location": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/shared\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.child.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.parent.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "members.count": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->isGroup() && !$object->isDynamic() && $object->count() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "name": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% new test 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "eq.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% new test 2)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "contains": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% -)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "help": "possible variables to bring in as argument: $$value$$ \/ $$ipv4$$ \/ $$ipv6$$ \/ $$value.no-netmask$$ \/ $$netmask$$ \/ $$netmask.blank32$$",
                            "ci": {
                                "fString": "(%PROP% \/n-\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.in.file": {
                            "Function": {},
                            "arg": true
                        }
                    }
                },
                "netmask": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "!$object->isGroup() && $object->isType_ipNetmask() && $object->getNetworkMask() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "object": {
                    "operators": {
                        "is.unused": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.unused.recursive": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.group": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.region": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.dynamic": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.tmp": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.ip-range": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.ip-netmask": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.fqdn": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.ip-wildcard": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.ipv4": {
                            "Function": {},
                            "arg": false
                        },
                        "is.ipv6": {
                            "Function": {},
                            "arg": false
                        },
                        "overrides.upper.level": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "overriden.at.lower.level": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.member.of": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.recursive.member.of": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp-in-grp-test-1)",
                                "input": "input\/panorama-8.0-merger.xml"
                            }
                        }
                    }
                },
                "refcount": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->countReferences() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reflocation": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches",
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.only": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches",
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refobjectname": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object name matches refobjectname",
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.only": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if RUE if object name matches only refobjectname",
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.recursive": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object name matches refobjectname",
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refstore": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% rulestore )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reftype": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "tag": {
                    "operators": {
                        "has": {
                            "Function": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->tags->parentCentralStore->find('!value!');",
                            "ci": {
                                "fString": "(%PROP% grp.shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% test)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/grp\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "tag.count": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->tags->count() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "value": {
                    "operators": {
                        "string.eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "ip4.match.exact": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "ip4.included-in": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "ip4.includes-full": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "ip4.includes-full-or-partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "string.regex": {
                            "Function": {},
                            "arg": true
                        },
                        "is.included-in.name": {
                            "Function": {},
                            "arg": false
                        },
                        "is.in.file": {
                            "Function": {},
                            "arg": true
                        },
                        "has.wrong.network": {
                            "Function": {},
                            "arg": false
                        }
                    }
                }
            }
        },
        "service": {
            "action": {
                "addobjectwhereused": {
                    "name": "addObjectWhereUsed",
                    "MainFunction": {},
                    "args": {
                        "objectName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "decommission": {
                    "name": "decommission",
                    "MainFunction": {},
                    "args": {
                        "file": {
                            "type": "string",
                            "default": "false"
                        }
                    }
                },
                "delete": {
                    "name": "delete",
                    "MainFunction": {}
                },
                "delete-force": {
                    "name": "delete-Force",
                    "MainFunction": {}
                },
                "deleteforce": {
                    "name": "deleteForce",
                    "MainFunction": {},
                    "deprecated": "this filter \"secprof is.profile\" is deprecated, you should use \"secprof type.is.profile\" instead!"
                },
                "description-append": {
                    "name": "description-Append",
                    "MainFunction": {},
                    "args": {
                        "text": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "description-delete": {
                    "name": "description-Delete",
                    "MainFunction": {}
                },
                "display": {
                    "name": "display",
                    "MainFunction": {}
                },
                "displayreferences": {
                    "name": "displayReferences",
                    "MainFunction": {}
                },
                "exporttoexcel": {
                    "name": "exportToExcel",
                    "MainFunction": {},
                    "GlobalInitFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "filename": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "additionalFields": {
                            "type": "pipeSeparatedList",
                            "subtype": "string",
                            "default": "*NONE*",
                            "choices": [
                                "WhereUsed",
                                "UsedInLocation"
                            ],
                            "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - WhereUsed : list places where object is used (rules, groups ...)\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n"
                        }
                    }
                },
                "move": {
                    "name": "move",
                    "MainFunction": {},
                    "args": {
                        "location": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "mode": {
                            "type": "string",
                            "default": "skipIfConflict",
                            "choices": [
                                "skipIfConflict",
                                "removeIfMatch",
                                "removeIfNumericalMatch"
                            ]
                        }
                    }
                },
                "name-addprefix": {
                    "name": "name-addPrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-addsuffix": {
                    "name": "name-addSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removeprefix": {
                    "name": "name-removePrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removesuffix": {
                    "name": "name-removeSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-rename": {
                    "name": "name-Rename",
                    "MainFunction": {},
                    "args": {
                        "stringFormula": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n  - $$destinationport$$ : destination Port\n  - $$protocol$$ : service protocol\n  - $$sourceport$$ : source Port\n  - $$value$$ : value of the object\n"
                        }
                    },
                    "help": ""
                },
                "name-replace-character": {
                    "name": "name-Replace-Character",
                    "MainFunction": {},
                    "args": {
                        "search": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "replace": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    },
                    "help": ""
                },
                "removewhereused": {
                    "name": "removeWhereUsed",
                    "MainFunction": {},
                    "args": {
                        "actionIfLastMemberInRule": {
                            "type": "string",
                            "default": "delete",
                            "choices": [
                                "delete",
                                "disable",
                                "setAny"
                            ]
                        }
                    }
                },
                "replacebymembersanddelete": {
                    "name": "replaceByMembersAndDelete",
                    "MainFunction": {}
                },
                "replacegroupbyservice": {
                    "name": "replaceGroupByService",
                    "MainFunction": {}
                },
                "replacewithobject": {
                    "name": "replaceWithObject",
                    "MainFunction": {},
                    "args": {
                        "objectName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "sourceport-delete": {
                    "name": "sourceport-delete",
                    "MainFunction": {}
                },
                "sourceport-set": {
                    "name": "sourceport-set",
                    "MainFunction": {},
                    "args": {
                        "sourceportValue": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "tag-add": {
                    "name": "tag-Add",
                    "section": "tag",
                    "MainFunction": {},
                    "args": {
                        "tagName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "tag-add-force": {
                    "name": "tag-Add-Force",
                    "section": "tag",
                    "MainFunction": {},
                    "args": {
                        "tagName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "tag-remove": {
                    "name": "tag-Remove",
                    "section": "tag",
                    "MainFunction": {},
                    "args": {
                        "tagName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "tag-remove-all": {
                    "name": "tag-Remove-All",
                    "section": "tag",
                    "MainFunction": {}
                },
                "tag-remove-regex": {
                    "name": "tag-Remove-Regex",
                    "section": "tag",
                    "MainFunction": {},
                    "args": {
                        "regex": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "timeout-set": {
                    "name": "timeout-set",
                    "MainFunction": {},
                    "args": {
                        "timeoutValue": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                }
            },
            "filter": {
                "description": {
                    "operators": {
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/test\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.empty": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "location": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/shared\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.child.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.parent.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "members.count": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->isGroup() && $object->count() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "name": {
                    "operators": {
                        "is.in.file": {
                            "Function": {},
                            "arg": true
                        },
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% tcp-80)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "eq.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% udp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "contains": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% udp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/tcp\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "object": {
                    "operators": {
                        "is.unused": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.unused.recursive": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.member.of": {
                            "Function": {},
                            "arg": true
                        },
                        "is.recursive.member.of": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp-in-grp-srv)",
                                "input": "input\/panorama-8.0-merger.xml"
                            }
                        },
                        "is.group": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.tcp": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.udp": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.tmp": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.srcport": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "overrides.upper.level": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "overriden.at.lower.level": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refcount": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->countReferences() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reflocation": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.only": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refstore": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% rulestore )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reftype": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "sourceport.value": {
                    "operators": {
                        "string.eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 80)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        ">,<,=,!": {
                            "eval": "!$object->isGroup() && $object->getSourcePort() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.single.port": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.port.range": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.comma.separated": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/tcp\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "tag": {
                    "operators": {
                        "has": {
                            "Function": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->tags->parentCentralStore->find('!value!');"
                        },
                        "has.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% test )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/grp\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "tag.count": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->tags->count() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "timeout": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false
                        }
                    }
                },
                "timeout.value": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "!$object->isGroup() && $object->getTimeout() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "value": {
                    "operators": {
                        "string.eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 80)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        ">,<,=,!": {
                            "eval": "!$object->isGroup() && $object->getDestPort() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.single.port": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.port.range": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.comma.separated": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/tcp\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "value.length": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "!$object->isGroup() && strlen($object->getDestPort()) !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        },
        "tag": {
            "action": {
                "color-set": {
                    "name": "Color-set",
                    "MainFunction": {},
                    "args": {
                        "color": {
                            "type": "string",
                            "default": "*nodefault*",
                            "choices": [
                                "none",
                                "red",
                                "green",
                                "blue",
                                "yellow",
                                "copper",
                                "orange",
                                "purple",
                                "gray",
                                "light green",
                                "cyan",
                                "light gray",
                                "blue gray",
                                "lime",
                                "black",
                                "gold",
                                "brown",
                                "dark green"
                            ]
                        }
                    }
                },
                "comments-add": {
                    "name": "Comments-add",
                    "MainFunction": {},
                    "args": {
                        "comments": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "comments-delete": {
                    "name": "Comments-delete",
                    "MainFunction": {}
                },
                "create": {
                    "name": "create",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "name": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "delete": {
                    "name": "delete",
                    "MainFunction": {}
                },
                "deleteforce": {
                    "name": "deleteForce",
                    "MainFunction": {}
                },
                "display": {
                    "name": "display",
                    "MainFunction": {}
                },
                "displayreferences": {
                    "name": "displayReferences",
                    "MainFunction": {}
                },
                "exporttoexcel": {
                    "name": "exportToExcel",
                    "MainFunction": {},
                    "GlobalInitFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "filename": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "additionalFields": {
                            "type": "pipeSeparatedList",
                            "subtype": "string",
                            "default": "*NONE*",
                            "choices": [
                                "WhereUsed",
                                "UsedInLocation"
                            ],
                            "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - WhereUsed : list places where object is used (rules, groups ...)\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n"
                        }
                    }
                },
                "move": {
                    "name": "move",
                    "MainFunction": {},
                    "args": {
                        "location": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "mode": {
                            "type": "string",
                            "default": "skipIfConflict",
                            "choices": [
                                "skipIfConflict",
                                "removeIfMatch"
                            ]
                        }
                    }
                },
                "name-addprefix": {
                    "name": "name-addPrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-addsuffix": {
                    "name": "name-addSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removeprefix": {
                    "name": "name-removePrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removesuffix": {
                    "name": "name-removeSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-tolowercase": {
                    "name": "name-toLowerCase",
                    "MainFunction": {}
                },
                "name-toucwords": {
                    "name": "name-toUCWords",
                    "MainFunction": {}
                },
                "name-touppercase": {
                    "name": "name-toUpperCase",
                    "MainFunction": {}
                },
                "replace-with-object": {
                    "name": "replace-With-Object",
                    "MainFunction": {},
                    "args": {
                        "objectName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                }
            },
            "filter": {
                "color": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% none)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "comments": {
                    "operators": {
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/test\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.empty": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "location": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/shared\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.child.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.parent.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "name": {
                    "operators": {
                        "is.in.file": {
                            "Function": {},
                            "arg": true
                        },
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp.shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "eq.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp.shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "contains": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/-group\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "object": {
                    "operators": {
                        "is.unused": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.tmp": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refcount": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->countReferences() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reflocation": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.only": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refstore": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% rulestore )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reftype": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        },
        "rule": {
            "action": {
                "app-add": {
                    "name": "app-Add",
                    "section": "app",
                    "MainFunction": {},
                    "args": {
                        "appName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "app-add-force": {
                    "name": "app-Add-Force",
                    "section": "app",
                    "MainFunction": {},
                    "args": {
                        "appName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "app-fix-dependencies": {
                    "name": "app-Fix-Dependencies",
                    "MainFunction": {},
                    "args": {
                        "fix": {
                            "type": "bool",
                            "default": "no"
                        }
                    }
                },
                "app-remove": {
                    "name": "app-Remove",
                    "section": "app",
                    "MainFunction": {},
                    "args": {
                        "appName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "app-remove-force-any": {
                    "name": "app-Remove-Force-Any",
                    "section": "app",
                    "MainFunction": {},
                    "args": {
                        "appName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "app-set-any": {
                    "name": "app-Set-Any",
                    "section": "app",
                    "MainFunction": {}
                },
                "app-usage-clear": {
                    "name": "app-Usage-clear",
                    "section": "app",
                    "MainFunction": {}
                },
                "bidirnat-split": {
                    "name": "biDirNat-Split",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "-DST"
                        }
                    }
                },
                "clone": {
                    "name": "clone",
                    "MainFunction": {},
                    "args": {
                        "before": {
                            "type": "bool",
                            "default": "yes"
                        },
                        "suffix": {
                            "type": "string",
                            "default": "-cloned"
                        }
                    }
                },
                "cloneforappoverride": {
                    "name": "cloneForAppOverride",
                    "MainFunction": {},
                    "args": {
                        "applicationName": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "specify the application to put in the resulting App-Override rule"
                        },
                        "restrictToListOfServices": {
                            "type": "string",
                            "default": "*sameAsInRule*",
                            "help": "you can limit which services will be included in the AppOverride rule by providing a #-separated list or a subquery prefixed with a @:\n  - svc1#svc2#svc3... : #-separated list\n  - @subquery1 : script will look for subquery1 filter which you have to provide as an additional argument to the script (ie: 'subquery1=(name eq tcp-50-web)')"
                        }
                    },
                    "help": "This action will take a Security rule and clone it as an App-Override rule. By default all services specified in the rule will also be in the AppOverride rule."
                },
                "copy": {
                    "name": "copy",
                    "MainFunction": {},
                    "args": {
                        "location": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "preORpost": {
                            "type": "string",
                            "default": "pre",
                            "choices": [
                                "pre",
                                "post"
                            ]
                        }
                    }
                },
                "delete": {
                    "name": "delete",
                    "MainFunction": {}
                },
                "description-append": {
                    "name": "description-Append",
                    "MainFunction": {},
                    "args": {
                        "text": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "newline": {
                            "type": "bool",
                            "default": "no"
                        }
                    }
                },
                "description-prepend": {
                    "name": "description-Prepend",
                    "MainFunction": {},
                    "args": {
                        "text": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "newline": {
                            "type": "bool",
                            "default": "no"
                        }
                    }
                },
                "description-replace-character": {
                    "name": "description-Replace-Character",
                    "MainFunction": {},
                    "args": {
                        "search": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "replace": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    },
                    "help": ""
                },
                "disabled-set": {
                    "name": "disabled-Set",
                    "MainFunction": {},
                    "args": {
                        "trueOrFalse": {
                            "type": "bool",
                            "default": "yes"
                        }
                    }
                },
                "disabled-set-fastapi": {
                    "name": "disabled-Set-FastAPI",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "trueOrFalse": {
                            "type": "bool",
                            "default": "yes"
                        }
                    }
                },
                "display": {
                    "name": "display",
                    "MainFunction": {},
                    "args": {
                        "additionalFields": {
                            "type": "pipeSeparatedList",
                            "subtype": "string",
                            "default": "*NONE*",
                            "choices": [
                                "ResolveAddressSummary",
                                "ResolveServiceSummary",
                                "ResolveApplicationSummary",
                                "ResolveScheduleSummary"
                            ],
                            "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - ResolveAddressSummary : fields with address objects will be resolved to IP addressed and summarized in a new column)\n  - ResolveServiceSummary : fields with service objects will be resolved to their value and summarized in a new column)\n  - ResolveApplicationSummary : fields with application objects will be resolved to their category and risk)\n  - ResolveScheduleSummary : fields with schedule objects will be resolved to their expire time)\n"
                        }
                    }
                },
                "dnat-set": {
                    "name": "DNat-set",
                    "MainFunction": {},
                    "args": {
                        "DNATtype": {
                            "type": "string",
                            "default": "static",
                            "help": "The following DNAT-type are possible:\n  - static\n  - dynamic\n  - none\n"
                        },
                        "objName": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "servicePort": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "dsri-set": {
                    "name": "dsri-Set",
                    "MainFunction": {},
                    "args": {
                        "trueOrFalse": {
                            "type": "bool",
                            "default": "no"
                        }
                    }
                },
                "dsri-set-fastapi": {
                    "name": "dsri-Set-FastAPI",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "trueOrFalse": {
                            "type": "bool",
                            "default": "no"
                        }
                    }
                },
                "dst-add": {
                    "name": "dst-Add",
                    "section": "address",
                    "MainFunction": {},
                    "args": {
                        "objName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    },
                    "help": "adds an object in the 'DESTINATION' field of a rule, if that field was set to 'ANY' it will then be replaced by this object."
                },
                "dst-negate-set": {
                    "name": "dst-Negate-Set",
                    "section": "address",
                    "MainFunction": {},
                    "args": {
                        "YESorNO": {
                            "type": "bool",
                            "default": "*nodefault*"
                        }
                    },
                    "help": "manages Destination Negation enablement"
                },
                "dst-remove": {
                    "name": "dst-Remove",
                    "section": "address",
                    "MainFunction": {},
                    "args": {
                        "objName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "dst-remove-force-any": {
                    "name": "dst-Remove-Force-Any",
                    "section": "address",
                    "MainFunction": {},
                    "args": {
                        "objName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "dst-remove-objects-matching-filter": {
                    "name": "dst-Remove-Objects-Matching-Filter",
                    "MainFunction": {},
                    "args": {
                        "filterName": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "specify the query that will be used to filter the objects to be removed"
                        }
                    },
                    "help": "this action will go through all objects and see if they match the query you input and then remove them if it's the case."
                },
                "dst-set-any": {
                    "name": "dst-set-Any",
                    "section": "address",
                    "MainFunction": {}
                },
                "enabled-set": {
                    "name": "enabled-Set",
                    "MainFunction": {},
                    "args": {
                        "trueOrFalse": {
                            "type": "bool",
                            "default": "yes"
                        }
                    }
                },
                "enabled-set-fastapi": {
                    "name": "enabled-Set-FastAPI",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "trueOrFalse": {
                            "type": "bool",
                            "default": "yes"
                        }
                    }
                },
                "exporttoexcel": {
                    "name": "exportToExcel",
                    "MainFunction": {},
                    "GlobalInitFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "filename": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "additionalFields": {
                            "type": "pipeSeparatedList",
                            "subtype": "string",
                            "default": "*NONE*",
                            "choices": [
                                "ResolveAddressSummary",
                                "ResolveServiceSummary",
                                "ResolveApplicationSummary",
                                "ResolveScheduleSummary"
                            ],
                            "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - ResolveAddressSummary : fields with address objects will be resolved to IP addressed and summarized in a new column)\n  - ResolveServiceSummary : fields with service objects will be resolved to their value and summarized in a new column)\n  - ResolveApplicationSummary : fields with application objects will be resolved to their category and risk)\n  - ResolveScheduleSummary : fields with schedule objects will be resolved to their expire time)\n"
                        }
                    }
                },
                "from-add": {
                    "name": "from-Add",
                    "section": "zone",
                    "MainFunction": {},
                    "args": {
                        "zoneName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    },
                    "help": "Adds a zone in the 'FROM' field of a rule. If FROM was set to ANY then it will be replaced by zone in argument.Zone must be existing already or script will out an error. Use action from-add-force if you want to add a zone that does not not exist."
                },
                "from-add-force": {
                    "name": "from-Add-Force",
                    "section": "zone",
                    "MainFunction": {},
                    "args": {
                        "zoneName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    },
                    "help": "Adds a zone in the 'FROM' field of a rule. If FROM was set to ANY then it will be replaced by zone in argument."
                },
                "from-calculate-zones": {
                    "name": "from-calculate-zones",
                    "section": "zone",
                    "MainFunction": {},
                    "args": {
                        "mode": {
                            "type": "string",
                            "default": "append",
                            "choices": [
                                "replace",
                                "append",
                                "show",
                                "unneeded-tag-add"
                            ],
                            "help": "Will determine what to do with resolved zones : show them, replace them in the rule , only append them (removes none but adds missing ones) or tag-add for unneeded zones"
                        },
                        "virtualRouter": {
                            "type": "string",
                            "default": "*autodetermine*",
                            "help": "Can optionally be provided if script cannot find which virtualRouter it should be using (ie: there are several VR in same VSYS)"
                        },
                        "template": {
                            "type": "string",
                            "default": "*notPanorama*",
                            "help": "When you are using Panorama then 1 or more templates could apply to a DeviceGroup, in such a case you may want to specify which Template name to use.\nBeware that if the Template is overriden or if you are not using Templates then you will want load firewall config in lieu of specifying a template. \nFor this, give value 'api@XXXXX' where XXXXX is serial number of the Firewall device number you want to use to calculate zones.\nIf you don't want to use API but have firewall config file on your computer you can then specify file@\/folderXYZ\/config.xml."
                        },
                        "vsys": {
                            "type": "string",
                            "default": "*autodetermine*",
                            "help": "specify vsys when script cannot autodetermine it or when you when to manually override"
                        }
                    },
                    "help": "This Action will use routing tables to resolve zones. When the program cannot find all parameters by itself (like vsys or template name you will have ti manually provide them.\n\nUsage examples:\n\n    - xxx-calculate-zones\n    - xxx-calculate-zones:replace\n    - xxx-calculate-zones:append,vr1\n    - xxx-calculate-zones:replace,vr3,api@0011C890C,vsys1\n    - xxx-calculate-zones:show,vr5,Datacenter_template\n    - xxx-calculate-zones:replace,vr3,file@firewall.xml,vsys1\n"
                },
                "from-remove": {
                    "name": "from-Remove",
                    "section": "zone",
                    "MainFunction": {},
                    "args": {
                        "zoneName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "from-remove-force-any": {
                    "name": "from-Remove-Force-Any",
                    "section": "zone",
                    "MainFunction": {},
                    "args": {
                        "zoneName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "from-replace": {
                    "name": "from-Replace",
                    "section": "zone",
                    "MainFunction": {},
                    "args": {
                        "zoneToReplaceName": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "zoneForReplacementName": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "force": {
                            "type": "bool",
                            "default": "no"
                        }
                    }
                },
                "from-set-any": {
                    "name": "from-Set-Any",
                    "section": "zone",
                    "MainFunction": {}
                },
                "hip-set": {
                    "name": "hip-Set",
                    "MainFunction": {},
                    "args": {
                        "HipProfile": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "invertpreandpost": {
                    "name": "invertPreAndPost",
                    "MainFunction": {}
                },
                "logend-disable": {
                    "name": "logEnd-Disable",
                    "section": "log",
                    "MainFunction": {},
                    "help": "disables 'log at end' in a security rule."
                },
                "logend-disable-fastapi": {
                    "name": "logend-Disable-FastAPI",
                    "section": "log",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "help": "disables 'log at end' in a security rule.\n'FastAPI' allows API commands to be sent all at once instead of a single call per rule, allowing much faster execution time."
                },
                "logend-enable": {
                    "name": "logEnd-Enable",
                    "section": "log",
                    "MainFunction": {},
                    "help": "enables 'log at end' in a security rule."
                },
                "logend-enable-fastapi": {
                    "name": "logend-Enable-FastAPI",
                    "section": "log",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "help": "enables 'log at end' in a security rule.\n'FastAPI' allows API commands to be sent all at once instead of a single call per rule, allowing much faster execution time."
                },
                "logsetting-disable": {
                    "name": "logSetting-disable",
                    "section": "log",
                    "MainFunction": {},
                    "help": "Remove log setting\/forwarding profile of a Security rule if any."
                },
                "logsetting-set": {
                    "name": "logSetting-set",
                    "section": "log",
                    "MainFunction": {},
                    "args": {
                        "profName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    },
                    "help": "Sets log setting\/forwarding profile of a Security rule to the value specified."
                },
                "logsetting-set-fastapi": {
                    "name": "logSetting-set-FastAPI",
                    "section": "log",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "profName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    },
                    "help": "Sets log setting\/forwarding profile of a Security rule to the value specified."
                },
                "logstart-disable": {
                    "name": "logStart-Disable",
                    "section": "log",
                    "MainFunction": {},
                    "help": "enables \"log at start\" in a security rule"
                },
                "logstart-disable-fastapi": {
                    "name": "logStart-Disable-FastAPI",
                    "section": "log",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "help": "disables 'log at start' in a security rule.\n'FastAPI' allows API commands to be sent all at once instead of a single call per rule, allowing much faster execution time."
                },
                "logstart-enable": {
                    "name": "logStart-Enable",
                    "section": "log",
                    "MainFunction": {},
                    "help": "disables \"log at start\" in a security rule"
                },
                "logstart-enable-fastapi": {
                    "name": "logStart-Enable-FastAPI",
                    "section": "log",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "help": "enables 'log at start' in a security rule.\n'FastAPI' allows API commands to be sent all at once instead of a single call per rule, allowing much faster execution time."
                },
                "move": {
                    "name": "move",
                    "MainFunction": {},
                    "args": {
                        "location": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "preORpost": {
                            "type": "string",
                            "default": "pre",
                            "choices": [
                                "pre",
                                "post"
                            ]
                        }
                    }
                },
                "name-addprefix": {
                    "name": "name-addPrefix",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "text": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "accept63characters": {
                            "type": "bool",
                            "default": "false",
                            "help": "This bool is used to allow longer rule name for PAN-OS starting with version 8.1."
                        }
                    }
                },
                "name-addsuffix": {
                    "name": "name-addSuffix",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "text": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "accept63characters": {
                            "type": "bool",
                            "default": "false",
                            "help": "This bool is used to allow longer rule name for PAN-OS starting with version 8.1."
                        }
                    }
                },
                "name-append": {
                    "name": "name-Append",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "text": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "accept63characters": {
                            "type": "bool",
                            "default": "false",
                            "help": "This bool is used to allow longer rule name for PAN-OS starting with version 8.1."
                        }
                    },
                    "deprecated": "this action \"name-Append\" is deprecated, you should use \"name-addSuffix\" instead!"
                },
                "name-prepend": {
                    "name": "name-Prepend",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "text": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "accept63characters": {
                            "type": "bool",
                            "default": "false",
                            "help": "This bool is used to allow longer rule name for PAN-OS starting with version 8.1."
                        }
                    },
                    "deprecated": "this action \"name-Prepend\" is deprecated, you should use \"name-addPrefix\" instead!"
                },
                "name-removeprefix": {
                    "name": "name-removePrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removesuffix": {
                    "name": "name-removeSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-rename": {
                    "name": "name-Rename",
                    "GlobalInitFunction": {},
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "stringFormula": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n  - $$sequential.number$$ : sequential number - starting with 1\n"
                        },
                        "accept63characters": {
                            "type": "bool",
                            "default": "false",
                            "help": "This bool is used to allow longer rule name for PAN-OS starting with version 8.1."
                        }
                    },
                    "help": ""
                },
                "name-replace-character": {
                    "name": "name-Replace-Character",
                    "GlobalInitFunction": {},
                    "MainFunction": {},
                    "args": {
                        "search": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "replace": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    },
                    "help": ""
                },
                "position-move-after": {
                    "name": "position-Move-After",
                    "MainFunction": {},
                    "GlobalInitFunction": {},
                    "args": {
                        "rulename": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "position-move-before": {
                    "name": "position-Move-Before",
                    "MainFunction": {},
                    "args": {
                        "rulename": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "position-move-to-bottom": {
                    "name": "position-Move-to-Bottom",
                    "MainFunction": {}
                },
                "position-move-to-top": {
                    "name": "position-Move-to-Top",
                    "MainFunction": {},
                    "GlobalInitFunction": {}
                },
                "qosmarking-remove": {
                    "name": "qosMarking-Remove",
                    "MainFunction": {}
                },
                "qosmarking-set": {
                    "name": "qosMarking-Set",
                    "MainFunction": {},
                    "args": {
                        "arg1": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "arg2": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "ruletype-change": {
                    "name": "ruleType-Change",
                    "MainFunction": {},
                    "args": {
                        "text": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "schedule-remove": {
                    "name": "schedule-Remove",
                    "MainFunction": {}
                },
                "schedule-set": {
                    "name": "schedule-Set",
                    "MainFunction": {},
                    "args": {
                        "Schedule": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "securityprofile-group-set": {
                    "name": "securityProfile-Group-Set",
                    "MainFunction": {},
                    "args": {
                        "profName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "securityprofile-group-set-fastapi": {
                    "name": "securityProfile-Group-Set-FastAPI",
                    "section": "log",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "profName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "securityprofile-group-set-force": {
                    "name": "securityProfile-Group-Set-Force",
                    "MainFunction": {},
                    "args": {
                        "profName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "securityprofile-profile-set": {
                    "name": "securityProfile-Profile-Set",
                    "MainFunction": {},
                    "args": {
                        "type": {
                            "type": "string",
                            "default": "*nodefault*",
                            "choices": [
                                "virus",
                                "vulnerability",
                                "url-filtering",
                                "data-filtering",
                                "file-blocking",
                                "spyware",
                                "wildfire"
                            ]
                        },
                        "profName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "securityprofile-remove": {
                    "name": "securityProfile-Remove",
                    "MainFunction": {},
                    "args": {
                        "type": {
                            "type": "string",
                            "default": "any",
                            "choices": [
                                "any",
                                "virus",
                                "vulnerability",
                                "url-filtering",
                                "data-filtering",
                                "file-blocking",
                                "spyware",
                                "wildfire"
                            ]
                        }
                    }
                },
                "securityprofile-remove-fastapi": {
                    "name": "securityProfile-Remove-FastAPI",
                    "MainFunction": {},
                    "GlobalFinishFunction": {}
                },
                "securityprofile-replace-by-group": {
                    "name": "securityProfile-replace-by-Group",
                    "MainFunction": {}
                },
                "service-add": {
                    "name": "service-Add",
                    "section": "service",
                    "MainFunction": {},
                    "args": {
                        "svcName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "service-remove": {
                    "name": "service-Remove",
                    "section": "service",
                    "MainFunction": {},
                    "args": {
                        "svcName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "service-remove-force-any": {
                    "name": "service-Remove-Force-Any",
                    "section": "service",
                    "MainFunction": {},
                    "args": {
                        "svcName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "service-remove-objects-matching-filter": {
                    "name": "service-Remove-Objects-Matching-Filter",
                    "MainFunction": {},
                    "args": {
                        "filterName": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "specify the query that will be used to filter the objects to be removed - \nexample: 'actions=service-remove-objects-matching-filter:subquery1,true' 'subquery1=(value > 600) && (object is.udp) && (value is.single.port)'"
                        },
                        "forceAny": {
                            "type": "bool",
                            "default": "false"
                        }
                    },
                    "help": "this action will go through all objects and see if they match the query you input and then remove them if it's the case."
                },
                "service-set-any": {
                    "name": "service-Set-Any",
                    "section": "service",
                    "MainFunction": {}
                },
                "service-set-appdefault": {
                    "name": "service-Set-AppDefault",
                    "section": "service",
                    "MainFunction": {}
                },
                "src-add": {
                    "name": "src-Add",
                    "section": "address",
                    "MainFunction": {},
                    "args": {
                        "objName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    },
                    "help": "adds an object in the 'SOURCE' field of a rule, if that field was set to 'ANY' it will then be replaced by this object."
                },
                "src-dst-swap": {
                    "name": "src-dst-swap",
                    "section": "address",
                    "MainFunction": {},
                    "help": "moves all source objects to destination and reverse."
                },
                "src-negate-set": {
                    "name": "src-Negate-Set",
                    "section": "address",
                    "MainFunction": {},
                    "args": {
                        "YESorNO": {
                            "type": "bool",
                            "default": "*nodefault*"
                        }
                    },
                    "help": "manages Source Negation enablement"
                },
                "src-remove": {
                    "name": "src-Remove",
                    "section": "address",
                    "MainFunction": {},
                    "args": {
                        "objName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "src-remove-force-any": {
                    "name": "src-Remove-Force-Any",
                    "section": "address",
                    "MainFunction": {},
                    "args": {
                        "objName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "src-remove-objects-matching-filter": {
                    "name": "src-Remove-Objects-Matching-Filter",
                    "MainFunction": {},
                    "args": {
                        "filterName": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "specify the query that will be used to filter the objects to be removed"
                        }
                    },
                    "help": "this action will go through all objects and see if they match the query you input and then remove them if it's the case."
                },
                "src-set-any": {
                    "name": "src-set-Any",
                    "section": "address",
                    "MainFunction": {}
                },
                "tag-add": {
                    "name": "tag-Add",
                    "section": "tag",
                    "MainFunction": {},
                    "args": {
                        "tagName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "tag-add-force": {
                    "name": "tag-Add-Force",
                    "section": "tag",
                    "MainFunction": {},
                    "args": {
                        "tagName": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "tagColor": {
                            "type": "string",
                            "default": "none"
                        }
                    }
                },
                "tag-remove": {
                    "name": "tag-Remove",
                    "section": "tag",
                    "MainFunction": {},
                    "args": {
                        "tagName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "tag-remove-all": {
                    "name": "tag-Remove-All",
                    "section": "tag",
                    "MainFunction": {}
                },
                "tag-remove-regex": {
                    "name": "tag-Remove-Regex",
                    "section": "tag",
                    "MainFunction": {},
                    "args": {
                        "regex": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "target-add-device": {
                    "name": "target-Add-Device",
                    "section": "target",
                    "MainFunction": {},
                    "args": {
                        "serial": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "vsys": {
                            "type": "string",
                            "default": "*NULL*",
                            "help": "if target firewall is single VSYS you should ignore this argument, otherwise just input it"
                        }
                    }
                },
                "target-negate-set": {
                    "name": "target-Negate-Set",
                    "section": "target",
                    "MainFunction": {},
                    "args": {
                        "trueOrFalse": {
                            "type": "bool",
                            "default": "*nodefault*"
                        }
                    }
                },
                "target-remove-device": {
                    "name": "target-Remove-Device",
                    "section": "target",
                    "MainFunction": {},
                    "args": {
                        "serial": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "vsys": {
                            "type": "string",
                            "default": "*NULL*"
                        }
                    }
                },
                "target-set-any": {
                    "name": "target-Set-Any",
                    "section": "target",
                    "MainFunction": {}
                },
                "to-add": {
                    "name": "to-Add",
                    "section": "zone",
                    "MainFunction": {},
                    "args": {
                        "zoneName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    },
                    "help": "Adds a zone in the 'TO' field of a rule. If TO was set to ANY then it will be replaced by zone in argument.Zone must be existing already or script will out an error. Use action to-add-force if you want to add a zone that does not not exist."
                },
                "to-add-force": {
                    "name": "to-Add-Force",
                    "section": "zone",
                    "MainFunction": {},
                    "args": {
                        "zoneName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    },
                    "help": "Adds a zone in the 'FROM' field of a rule. If FROM was set to ANY then it will be replaced by zone in argument."
                },
                "to-calculate-zones": {
                    "name": "to-calculate-zones",
                    "section": "zone",
                    "MainFunction": {},
                    "args": {
                        "mode": {
                            "type": "string",
                            "default": "append",
                            "choices": [
                                "replace",
                                "append",
                                "show",
                                "unneeded-tag-add"
                            ],
                            "help": "Will determine what to do with resolved zones : show them, replace them in the rule , only append them (removes none but adds missing ones) or tag-add for unneeded zones"
                        },
                        "virtualRouter": {
                            "type": "string",
                            "default": "*autodetermine*",
                            "help": "Can optionally be provided if script cannot find which virtualRouter it should be using (ie: there are several VR in same VSYS)"
                        },
                        "template": {
                            "type": "string",
                            "default": "*notPanorama*",
                            "help": "When you are using Panorama then 1 or more templates could apply to a DeviceGroup, in such a case you may want to specify which Template name to use.\nBeware that if the Template is overriden or if you are not using Templates then you will want load firewall config in lieu of specifying a template. \nFor this, give value 'api@XXXXX' where XXXXX is serial number of the Firewall device number you want to use to calculate zones.\nIf you don't want to use API but have firewall config file on your computer you can then specify file@\/folderXYZ\/config.xml."
                        },
                        "vsys": {
                            "type": "string",
                            "default": "*autodetermine*",
                            "help": "specify vsys when script cannot autodetermine it or when you when to manually override"
                        }
                    },
                    "help": "This Action will use routing tables to resolve zones. When the program cannot find all parameters by itself (like vsys or template name you will have ti manually provide them.\n\nUsage examples:\n\n    - xxx-calculate-zones\n    - xxx-calculate-zones:replace\n    - xxx-calculate-zones:append,vr1\n    - xxx-calculate-zones:replace,vr3,api@0011C890C,vsys1\n    - xxx-calculate-zones:show,vr5,Datacenter_template\n    - xxx-calculate-zones:replace,vr3,file@firewall.xml,vsys1\n"
                },
                "to-remove": {
                    "name": "to-Remove",
                    "section": "zone",
                    "MainFunction": {},
                    "args": {
                        "zoneName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "to-remove-force-any": {
                    "name": "to-Remove-Force-Any",
                    "section": "zone",
                    "MainFunction": {},
                    "args": {
                        "zoneName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "to-replace": {
                    "name": "to-Replace",
                    "section": "zone",
                    "MainFunction": {},
                    "args": {
                        "zoneToReplaceName": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "zoneForReplacementName": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "force": {
                            "type": "bool",
                            "default": "no"
                        }
                    }
                },
                "to-set-any": {
                    "name": "to-Set-Any",
                    "section": "zone",
                    "MainFunction": {}
                },
                "user-add": {
                    "name": "user-Add",
                    "MainFunction": {},
                    "args": {
                        "userName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "user-check-ldap": {
                    "name": "user-check-ldap",
                    "GlobalInitFunction": {},
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "actionType": {
                            "type": "string",
                            "default": "show",
                            "help": "'show' and 'remove' are supported."
                        },
                        "ldapUser": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "define LDAP user for authentication to server"
                        },
                        "ldapServer": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "LDAP server fqdn \/ IP"
                        },
                        "dn": {
                            "type": "string",
                            "default": "OU=TEST;DC=domain;DC=local",
                            "help": "full OU to an LDAP part, sparated with ';' - this is a specific setting"
                        },
                        "filtercriteria": {
                            "type": "string",
                            "default": "mailNickname",
                            "help": "Domain\\username - specify the search filter criteria where your Security Rule defined user name can be found in LDAP"
                        },
                        "existentUser": {
                            "type": "bool",
                            "default": "false",
                            "help": "users no longer available in LDAP => false | users available in LDAP => true, e.g. if users are disabled and available in a specific LDAP group"
                        }
                    }
                },
                "user-remove": {
                    "name": "user-remove",
                    "MainFunction": {},
                    "args": {
                        "userName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "user-set-any": {
                    "name": "user-set-any",
                    "MainFunction": {}
                },
                "xml-extract": {
                    "name": "xml-extract",
                    "GlobalInitFunction": {},
                    "MainFunction": {},
                    "GlobalFinishFunction": {}
                }
            },
            "filter": {
                "action": {
                    "operators": {
                        "is.deny": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.negative": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.allow": {
                            "Function": {},
                            "arg": false
                        },
                        "is.drop": {
                            "Function": {},
                            "arg": false
                        }
                    }
                },
                "app": {
                    "operators": {
                        "is.any": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->apps->parentCentralStore->find('!value!');"
                        },
                        "has.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% icmp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/test-\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.recursive": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ssl)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "includes.full.or.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ssl)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "includes.full.or.partial.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ssl)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "included-in.full.or.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ssl)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "included-in.full.or.partial.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ssl)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "custom.has.signature": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "category.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% media)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "subcategory.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% gaming)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "technology.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% client-server)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "risk.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% client-server)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "characteristic.has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% evasive) ",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.missing.dependencies": {
                            "Function": {},
                            "arg": false
                        }
                    }
                },
                "description": {
                    "operators": {
                        "is.empty": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/input a string here\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "description.length": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "strlen($object->description() ) !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "dnat": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "dnathost": {
                    "operators": {
                        "has": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->owner->owner->addressStore->find('!value!');"
                        },
                        "included-in.full": {
                            "Function": {},
                            "arg": true,
                            "argDesc": "ie: 192.168.0.0\/24 | 192.168.50.10\/32 | 192.168.50.10 | 10.0.0.0-10.33.0.0",
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "included-in.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "included-in.full.or.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "includes.full": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "includes.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "includes.full.or.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "dst": {
                    "operators": {
                        "has": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->destination->parentCentralStore->find('!value!');"
                        },
                        "has.only": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->destination->parentCentralStore->find('!value!');"
                        },
                        "has.recursive": {
                            "eval": "$object->destination->hasObjectRecursive(!value!, false) === true",
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->destination->parentCentralStore->find('!value!');"
                        },
                        "has.recursive.regex": {
                            "Function": {},
                            "arg": true
                        },
                        "is.any": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.negated": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "included-in.full": {
                            "Function": {},
                            "arg": true,
                            "argDesc": "ie: 192.168.0.0\/24 | 192.168.50.10\/32 | 192.168.50.10 | 10.0.0.0-10.33.0.0",
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "included-in.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "included-in.full.or.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "includes.full": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "includes.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "includes.full.or.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.from.query": {
                            "Function": {},
                            "arg": true,
                            "help": "example: 'filter=(dst has.from.query subquery1)' 'subquery1=(value ip4.includes-full 10.10.0.1)'"
                        },
                        "has.recursive.from.query": {
                            "Function": {},
                            "arg": true
                        },
                        "is.fully.included.in.list": {
                            "Function": {},
                            "arg": true,
                            "argType": "commaSeparatedList"
                        },
                        "is.partially.or.fully.included.in.list": {
                            "Function": {},
                            "arg": true,
                            "argType": "commaSeparatedList"
                        },
                        "is.partially.included.in.list": {
                            "Function": {},
                            "arg": true,
                            "argType": "commaSeparatedList"
                        }
                    }
                },
                "dst-interface": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "from": {
                    "operators": {
                        "has": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->from->parentCentralStore->find('!value!');"
                        },
                        "has.only": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->from->parentCentralStore->find('!value!');"
                        },
                        "has.regex": {
                            "Function": {},
                            "arg": true
                        },
                        "is.any": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.in.file": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if rule name matches one of the names found in text file provided in argument"
                        },
                        "has.same.to.zone": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "from.count": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->from->count() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "location": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches the regular expression specified in argument",
                            "ci": {
                                "fString": "(%PROP%  \/DC\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.child.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.parent.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "log": {
                    "operators": {
                        "at.start": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "at.end": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "logprof": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is": {
                            "Function": {},
                            "arg": true,
                            "help": "return true if Log Forwarding Profile is the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  log_to_panorama)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "name": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if rule name matches the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  rule1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if rule name matches the regular expression provided in argument",
                            "ci": {
                                "fString": "(%PROP%  \/^example\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "eq.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP%  rule1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "contains": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP%  searchME)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.in.file": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if rule name matches one of the names found in text file provided in argument"
                        }
                    }
                },
                "rule": {
                    "operators": {
                        "is.prerule": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.postrule": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.disabled": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.enabled": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.dsri": {
                            "Function": {},
                            "arg": false,
                            "help": "return TRUE if Disable Server Response Inspection has been enabled"
                        },
                        "is.bidir.nat": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.source.nat": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.destination.nat": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.universal": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.intrazone": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.interzone": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.unused.fast": {
                            "Function": {},
                            "arg": false
                        }
                    }
                },
                "schedule": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true
                        },
                        "is.set": {
                            "Function": {},
                            "arg": false
                        },
                        "has.regex": {
                            "Function": {},
                            "arg": true
                        },
                        "is.expired": {
                            "Function": {},
                            "arg": false
                        },
                        "expire.in.days": {
                            "Function": {},
                            "arg": true
                        }
                    }
                },
                "secprof": {
                    "operators": {
                        "not.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.profile": {
                            "Function": {},
                            "arg": false,
                            "deprecated": "this filter \"secprof is.profile\" is deprecated, you should use \"secprof type.is.profile\" instead!",
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "type.is.profile": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.group": {
                            "Function": {},
                            "arg": false,
                            "deprecated": "this filter \"secprof is.group\" is deprecated, you should use \"secprof type.is.group\" instead!",
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "type.is.group": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "group.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% secgroup-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "av-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% av-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "as-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% as-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "url-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% url-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "wf-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% wf-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "vuln-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% vuln-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "file-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% vuln-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "data-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% vuln-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "av-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "as-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "url-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "wf-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "vuln-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "file-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "data-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "service": {
                    "operators": {
                        "has.from.query": {
                            "Function": {},
                            "arg": true,
                            "help": "example: 'filter=(service has.from.query subquery1)' 'subquery1=(value regex 8443)'"
                        },
                        "has.recursive.from.query": {
                            "Function": {},
                            "arg": true
                        },
                        "is.any": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.application-default": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->services->parentCentralStore->find('!value!');"
                        },
                        "has.only": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->services->parentCentralStore->find('!value!');"
                        },
                        "has.regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/tcp-\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.recursive": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% tcp-80)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.tcp.only": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.udp.only": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.tcp": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.udp": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.value.recursive": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 443)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.value": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 443)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.value.only": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 443)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "snat": {
                    "operators": {
                        "is.static": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.dynamic-ip": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.dynamic-ip-and-port": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "snathost": {
                    "operators": {
                        "has": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->owner->owner->addressStore->find('!value!');"
                        },
                        "has.from.query": {
                            "Function": {},
                            "arg": true,
                            "help": "example: 'filter=(snathost has.from.query subquery1)' 'subquery1=(netmask < 32)'"
                        }
                    }
                },
                "snathost.count": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->isNatRule() && $object->snathosts->count() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "src": {
                    "operators": {
                        "has": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->source->parentCentralStore->find('!value!');"
                        },
                        "has.only": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->source->parentCentralStore->find('!value!');"
                        },
                        "has.recursive": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->source->parentCentralStore->find('!value!');"
                        },
                        "has.recursive.regex": {
                            "Function": {},
                            "arg": true
                        },
                        "is.any": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.negated": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "included-in.full": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "included-in.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "included-in.full.or.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "includes.full": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "includes.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "includes.full.or.partial": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1.1.1.1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.fully.included.in.list": {
                            "Function": {},
                            "arg": true,
                            "argType": "commaSeparatedList"
                        },
                        "is.partially.or.fully.included.in.list": {
                            "Function": {},
                            "arg": true,
                            "argType": "commaSeparatedList"
                        },
                        "is.partially.included.in.list": {
                            "Function": {},
                            "arg": true,
                            "argType": "commaSeparatedList"
                        },
                        "has.from.query": {
                            "Function": {},
                            "arg": true,
                            "help": "example: 'filter=(src has.from.query subquery1)' 'subquery1=(value ip4.includes-full 10.10.0.1)'"
                        },
                        "has.recursive.from.query": {
                            "Function": {},
                            "arg": true
                        }
                    }
                },
                "tag": {
                    "operators": {
                        "has": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->tags->parentCentralStore->find('!value!');",
                            "ci": {
                                "fString": "(%PROP% test.tag)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% test.tag)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/test-\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "tag.count": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->tags->count() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "target": {
                    "operators": {
                        "is.any": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP%  00YC25C)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "timestamp-last-hit.fast": {
                    "operators": {
                        ">,<,=,!": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if rule name matches the specified timestamp MM\/DD\/YYYY [american] \/ DD-MM-YYYY [european] \/ 21 September 2021 \/ - 90 days"
                        }
                    }
                },
                "to": {
                    "operators": {
                        "has": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": {},
                            "help": "returns TRUE if field TO is using zone mentionned in argument. Ie: \"(to has Untrust)\""
                        },
                        "has.only": {
                            "eval": {},
                            "arg": true,
                            "argObjectFinder": "$objectFind=null;\n$objectFind=$object->to->parentCentralStore->find('!value!');"
                        },
                        "has.regex": {
                            "Function": {},
                            "arg": true
                        },
                        "is.any": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.in.file": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if rule name matches one of the names found in text file provided in argument"
                        },
                        "has.same.from.zone": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "to.count": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->to->count() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "url.category": {
                    "operators": {
                        "is.any": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% adult)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "user": {
                    "operators": {
                        "is.any": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.known": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.unknown": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.prelogon": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% CN=xyz,OU=Network)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/^test\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.in.file": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if rule name matches one of the names found in text file provided in argument"
                        }
                    }
                },
                "user.count": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->isSecurityRule() && $object->userID_count() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        },
        "zone": {
            "action": {
                "delete": {
                    "name": "delete",
                    "MainFunction": {}
                },
                "deleteforce": {
                    "name": "deleteForce",
                    "MainFunction": {}
                },
                "display": {
                    "name": "display",
                    "MainFunction": {}
                },
                "displayreferences": {
                    "name": "displayReferences",
                    "MainFunction": {}
                },
                "exporttoexcel": {
                    "name": "exportToExcel",
                    "MainFunction": {},
                    "GlobalInitFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "filename": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "additionalFields": {
                            "type": "pipeSeparatedList",
                            "subtype": "string",
                            "default": "*NONE*",
                            "choices": [
                                "WhereUsed",
                                "UsedInLocation",
                                "ResolveIP",
                                "NestedMembers"
                            ],
                            "help": "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n  - NestedMembers: lists all members, even the ones that may be included in nested groups\n  - ResolveIP\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n  - WhereUsed : list places where object is used (rules, groups ...)\n"
                        }
                    }
                },
                "logsetting-set": {
                    "name": "logsetting-Set",
                    "MainFunction": {},
                    "args": {
                        "logforwardingprofile-name": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "this argument can be also 'none' to remove the Log Setting back to PAN-OS default."
                        }
                    }
                },
                "name-addprefix": {
                    "name": "name-addPrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-addsuffix": {
                    "name": "name-addSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removeprefix": {
                    "name": "name-removePrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removesuffix": {
                    "name": "name-removeSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-rename": {
                    "name": "name-Rename",
                    "MainFunction": {},
                    "args": {
                        "stringFormula": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n"
                        }
                    },
                    "help": ""
                },
                "name-tolowercase": {
                    "name": "name-toLowerCase",
                    "MainFunction": {}
                },
                "name-toucwords": {
                    "name": "name-toUCWords",
                    "MainFunction": {}
                },
                "name-touppercase": {
                    "name": "name-toUpperCase",
                    "MainFunction": {}
                },
                "packetbufferprotection-set": {
                    "name": "PacketBufferProtection-Set",
                    "MainFunction": {},
                    "args": {
                        "PacketBufferProtection": {
                            "type": "bool",
                            "default": "*nodefault*"
                        }
                    }
                },
                "replacewithobject": {
                    "name": "replaceWithObject",
                    "MainFunction": {},
                    "args": {
                        "objectName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "zpp-set": {
                    "name": "zpp-Set",
                    "MainFunction": {},
                    "args": {
                        "ZPP-name": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                }
            },
            "filter": {
                "location": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/shared\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.child.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.parent.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "logprof": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is": {
                            "Function": {},
                            "arg": true,
                            "help": "return true if Log Forwarding Profile is the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  log_to_panorama)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "name": {
                    "operators": {
                        "is.in.file": {
                            "Function": {},
                            "arg": true
                        },
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp.shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "eq.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp.shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "contains": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/-group\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "object": {
                    "operators": {
                        "is.unused": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.tmp": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refcount": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->countReferences() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reflocation": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.only": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refstore": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% rulestore )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reftype": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        },
        "securityprofile": {
            "action": {
                "action-set": {
                    "name": "action-set",
                    "MainFunction": {},
                    "args": {
                        "action": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "allow, alert, block, continue, override"
                        },
                        "filter": {
                            "type": "string",
                            "default": "all",
                            "help": "all \/ all-[action] \/ category"
                        }
                    }
                },
                "delete": {
                    "name": "delete",
                    "MainFunction": {}
                },
                "deleteforce": {
                    "name": "deleteForce",
                    "MainFunction": {}
                },
                "display": {
                    "name": "display",
                    "MainFunction": {}
                },
                "displayreferences": {
                    "name": "displayReferences",
                    "MainFunction": {}
                },
                "exporttoexcel": {
                    "name": "exportToExcel",
                    "MainFunction": {},
                    "GlobalInitFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "filename": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "additionalFields": {
                            "type": "pipeSeparatedList",
                            "subtype": "string",
                            "default": "*NONE*",
                            "choices": [
                                "WhereUsed",
                                "UsedInLocation"
                            ],
                            "help": "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n  - WhereUsed : list places where object is used (rules, groups ...)\n"
                        }
                    }
                },
                "name-addprefix": {
                    "name": "name-addPrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-addsuffix": {
                    "name": "name-addSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removeprefix": {
                    "name": "name-removePrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removesuffix": {
                    "name": "name-removeSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-tolowercase": {
                    "name": "name-toLowerCase",
                    "MainFunction": {}
                },
                "name-toucwords": {
                    "name": "name-toUCWords",
                    "MainFunction": {}
                },
                "name-touppercase": {
                    "name": "name-toUpperCase",
                    "MainFunction": {}
                }
            },
            "filter": {
                "alert": {
                    "operators": {
                        "has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "block": {
                    "operators": {
                        "has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "continue": {
                    "operators": {
                        "has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "exception": {
                    "operators": {
                        "has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.set": {
                            "Function": {},
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "location": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/shared\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.child.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.parent.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "name": {
                    "operators": {
                        "is.in.file": {
                            "Function": {},
                            "arg": true
                        },
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp.shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "eq.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp.shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "contains": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/-group\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "object": {
                    "operators": {
                        "is.unused": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.tmp": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "override": {
                    "operators": {
                        "has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refcount": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->countReferences() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reflocation": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.only": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refstore": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% rulestore )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reftype": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        },
        "schedule": {
            "action": {
                "delete": {
                    "name": "delete",
                    "MainFunction": {}
                },
                "deleteforce": {
                    "name": "deleteForce",
                    "MainFunction": {}
                },
                "display": {
                    "name": "display",
                    "MainFunction": {}
                },
                "displayreferences": {
                    "name": "displayReferences",
                    "MainFunction": {}
                },
                "name-addprefix": {
                    "name": "name-addPrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-addsuffix": {
                    "name": "name-addSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removeprefix": {
                    "name": "name-removePrefix",
                    "MainFunction": {},
                    "args": {
                        "prefix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-removesuffix": {
                    "name": "name-removeSuffix",
                    "MainFunction": {},
                    "args": {
                        "suffix": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                },
                "name-tolowercase": {
                    "name": "name-toLowerCase",
                    "MainFunction": {}
                },
                "name-toucwords": {
                    "name": "name-toUCWords",
                    "MainFunction": {}
                },
                "name-touppercase": {
                    "name": "name-toUpperCase",
                    "MainFunction": {}
                },
                "replacewithobject": {
                    "name": "replaceWithObject",
                    "MainFunction": {},
                    "args": {
                        "objectName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                }
            },
            "filter": {
                "location": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/shared\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.child.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.parent.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "name": {
                    "operators": {
                        "is.in.file": {
                            "Function": {},
                            "arg": true
                        },
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp.shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "eq.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp.shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "contains": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/-group\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "object": {
                    "operators": {
                        "is.unused": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.expired": {
                            "Function": {},
                            "arg": false
                        },
                        "expire.in.days": {
                            "Function": {},
                            "arg": true
                        },
                        "is.tmp": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refcount": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->countReferences() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reflocation": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.only": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refstore": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% rulestore )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reftype": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        },
        "virtualwire": {
            "action": {
                "display": {
                    "name": "display",
                    "MainFunction": {}
                }
            },
            "filter": {
                "name": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ethernet1\/1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        },
        "routing": {
            "action": {
                "display": {
                    "name": "display",
                    "MainFunction": {}
                }
            },
            "filter": {
                "name": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ethernet1\/1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        },
        "interface": {
            "action": {
                "display": {
                    "name": "display",
                    "MainFunction": {}
                }
            },
            "filter": {
                "name": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ethernet1\/1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        },
        "device": {
            "action": {
                "addressstore-rewrite": {
                    "name": "addressstore-rewrite",
                    "GlobalInitFunction": {},
                    "MainFunction": {}
                },
                "cleanuprule-create-bp": {
                    "name": "cleanuprule-create-bp",
                    "GlobalInitFunction": {},
                    "MainFunction": {},
                    "args": {
                        "logprof": {
                            "type": "string",
                            "default": "default",
                            "help": "LogForwardingProfile name"
                        }
                    }
                },
                "devicegroup-create": {
                    "name": "devicegroup-create",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "name": {
                            "type": "string",
                            "default": "false"
                        },
                        "parentdg": {
                            "type": "string",
                            "default": "null"
                        }
                    }
                },
                "devicegroup-delete": {
                    "name": "devicegroup-delete",
                    "MainFunction": {}
                },
                "display": {
                    "name": "display",
                    "MainFunction": {}
                },
                "display-shadowrule": {
                    "name": "display-shadowrule",
                    "GlobalInitFunction": {},
                    "MainFunction": {}
                },
                "displayreferences": {
                    "name": "displayReferences",
                    "MainFunction": {}
                },
                "exportinventorytoexcel": {
                    "name": "exportInventoryToExcel",
                    "GlobalInitFunction": {},
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "filename": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "only usable with 'devicetype=manageddevice'"
                        }
                    }
                },
                "exportlicensetoexcel": {
                    "name": "exportLicenseToExcel",
                    "GlobalInitFunction": {},
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "filename": {
                            "type": "string",
                            "default": "*nodefault*",
                            "help": "only usable with 'devicetype=manageddevice'"
                        }
                    }
                },
                "exporttoexcel": {
                    "name": "exportToExcel",
                    "MainFunction": {},
                    "GlobalInitFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "filename": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "additionalFields": {
                            "type": "pipeSeparatedList",
                            "subtype": "string",
                            "default": "*NONE*",
                            "choices": [
                                "WhereUsed",
                                "UsedInLocation"
                            ],
                            "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - WhereUsed : list places where object is used (rules, groups ...)\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n"
                        }
                    }
                },
                "geoip-check": {
                    "name": "geoIP-check",
                    "GlobalInitFunction": {},
                    "MainFunction": {},
                    "args": {
                        "checkIP": {
                            "type": "string",
                            "default": "8.8.8.8",
                            "help": "checkIP is IPv4 or IPv6 host address"
                        }
                    }
                },
                "logforwardingprofile-create-bp": {
                    "name": "logforwardingprofile-create-bp",
                    "GlobalInitFunction": {},
                    "MainFunction": {},
                    "args": {
                        "shared": {
                            "type": "bool",
                            "default": "false",
                            "help": "if set to true; LogForwardingProfile is create at SHARED level; at least one DG must be available"
                        }
                    }
                },
                "securityprofile-create-alert-only": {
                    "name": "securityprofile-create-alert-only",
                    "GlobalInitFunction": {},
                    "MainFunction": {},
                    "args": {
                        "shared": {
                            "type": "bool",
                            "default": "false",
                            "help": "if set to true; securityProfiles are create at SHARED level; at least one DG must be available"
                        }
                    }
                },
                "template-add": {
                    "name": "template-add",
                    "MainFunction": {},
                    "args": {
                        "templateName": {
                            "type": "string",
                            "default": "false"
                        },
                        "position": {
                            "type": "string",
                            "default": "bottom"
                        }
                    }
                },
                "template-create": {
                    "name": "template-create",
                    "MainFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "name": {
                            "type": "string",
                            "default": "false"
                        }
                    }
                },
                "template-delete": {
                    "name": "template-delete",
                    "MainFunction": {}
                },
                "zoneprotectionprofile-create-bp": {
                    "name": "zoneprotectionprofile-create-bp",
                    "GlobalInitFunction": {},
                    "MainFunction": {}
                }
            },
            "filter": {
                "name": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp.shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/-group\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "templatestack": {
                    "operators": {
                        "has.member": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        },
        "securityprofilegroup": {
            "action": {
                "display": {
                    "name": "display",
                    "MainFunction": {}
                },
                "displayreferences": {
                    "name": "displayReferences",
                    "MainFunction": {}
                },
                "exporttoexcel": {
                    "name": "exportToExcel",
                    "MainFunction": {},
                    "GlobalInitFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "filename": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "additionalFields": {
                            "type": "pipeSeparatedList",
                            "subtype": "string",
                            "default": "*NONE*",
                            "choices": [
                                "WhereUsed",
                                "UsedInLocation"
                            ],
                            "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - WhereUsed : list places where object is used (rules, groups ...)\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n"
                        }
                    }
                },
                "securityprofile-remove": {
                    "name": "securityProfile-Remove",
                    "MainFunction": {},
                    "args": {
                        "type": {
                            "type": "string",
                            "default": "any",
                            "choices": [
                                "any",
                                "virus",
                                "vulnerability",
                                "url-filtering",
                                "data-filtering",
                                "file-blocking",
                                "spyware",
                                "wildfire"
                            ]
                        }
                    }
                },
                "securityprofile-set": {
                    "name": "securityProfile-Set",
                    "MainFunction": {},
                    "args": {
                        "type": {
                            "type": "string",
                            "default": "*nodefault*",
                            "choices": [
                                "virus",
                                "vulnerability",
                                "url-filtering",
                                "data-filtering",
                                "file-blocking",
                                "spyware",
                                "wildfire"
                            ]
                        },
                        "profName": {
                            "type": "string",
                            "default": "*nodefault*"
                        }
                    }
                }
            },
            "filter": {
                "location": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/shared\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.child.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.parent.of": {
                            "Function": {},
                            "arg": true,
                            "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                            "ci": {
                                "fString": "(%PROP%  Datacenter-Firewalls)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "name": {
                    "operators": {
                        "is.in.file": {
                            "Function": {},
                            "arg": true
                        },
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp.shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "eq.nocase": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp.shared-group1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "contains": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% grp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/-group\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "object": {
                    "operators": {
                        "is.unused": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.tmp": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refcount": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->countReferences() !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reflocation": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.only": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% shared )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "refstore": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% rulestore )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "reftype": {
                    "operators": {
                        "is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% securityrule )",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "secprof": {
                    "operators": {
                        "av-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% av-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "as-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% as-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "url-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% url-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "wf-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% wf-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "vuln-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% vuln-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "file-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% vuln-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "data-profile.is": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% vuln-production)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "av-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "as-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "url-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "wf-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "vuln-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "file-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "data-profile.is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        },
        "application": {
            "action": {
                "display": {
                    "name": "display",
                    "GlobalInitFunction": {},
                    "MainFunction": {},
                    "GlobalFinishFunction": {}
                },
                "displayreferences": {
                    "name": "displayReferences",
                    "MainFunction": {}
                },
                "move": {
                    "name": "move",
                    "MainFunction": {},
                    "args": {
                        "location": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "mode": {
                            "type": "string",
                            "default": "skipIfConflict",
                            "choices": [
                                "skipIfConflict"
                            ]
                        }
                    }
                }
            },
            "filter": {
                "apptag": {
                    "operators": {
                        "has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "characteristic": {
                    "operators": {
                        "has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% evasive) ",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "name": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ftp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "regex": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% \/tcp\/)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "object": {
                    "operators": {
                        "is.predefined": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.application-group": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.application-filter": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.application-custom": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.tmp": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "is.container": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has.member": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "risk": {
                    "operators": {
                        ">,<,=,!": {
                            "eval": "$object->risk !operator! !value!",
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% 1)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "subcategory": {
                    "operators": {
                        "is.ip-protocol": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "tcp": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "tcp_half_closed_timeout": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "tcp_secure": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "tcp_time_wait_timeout": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "tcp_timeout": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "timeout": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "type": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "udp": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        },
                        "has": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "udp_secure": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "udp_timeout": {
                    "operators": {
                        "is.set": {
                            "Function": {},
                            "arg": false,
                            "ci": {
                                "fString": "(%PROP%)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        },
        "threat": {
            "action": {
                "display": {
                    "name": "display",
                    "GlobalInitFunction": {},
                    "MainFunction": {},
                    "GlobalFinishFunction": {}
                },
                "displayreferences": {
                    "name": "displayReferences",
                    "MainFunction": {}
                },
                "exporttoexcel": {
                    "name": "exportToExcel",
                    "MainFunction": {},
                    "GlobalInitFunction": {},
                    "GlobalFinishFunction": {},
                    "args": {
                        "filename": {
                            "type": "string",
                            "default": "*nodefault*"
                        },
                        "additionalFields": {
                            "type": "pipeSeparatedList",
                            "subtype": "string",
                            "default": "*NONE*",
                            "choices": [
                                "WhereUsed",
                                "UsedInLocation"
                            ],
                            "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - WhereUsed : list places where object is used (rules, groups ...)\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n"
                        }
                    }
                }
            },
            "filter": {
                "category": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ftp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "default-action": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ftp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "name": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ftp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "severity": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ftp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                },
                "threatname": {
                    "operators": {
                        "eq": {
                            "Function": {},
                            "arg": true,
                            "ci": {
                                "fString": "(%PROP% ftp)",
                                "input": "input\/panorama-8.0.xml"
                            }
                        }
                    }
                }
            }
        }
    }



var additionalArguments = {
    "location": {
        "arg": {},
        "help": {}
    },
    "stats": {
        "help": {}
    },
    "shadow-reduceXML": {
        "help": {}
    },
    "shadow-json": {
        "help": {}
    },
    "shadow-ignoreinvalidaddressobjects": {
        "help": {}
    },
    "shadow-enablexmlduplicatedeletion": {
        "help": {}
    },
}

var migrationVendors = {
    "ciscoasa": {
        "help": {}
    },
    "ciscoswitch": {
        "help": {}
    },
    "ciscoisr": {
        "help": {}
    },
    "netscreen": {
        "help": {}
    },
    "srx": {
        "help": {}
    },
    "stonesoft": {
        "help": {}
    },
    "cp": {
        "help": {}
    },
    "cp-r80": {
        "help": {}
    },
    "fortinet": {
        "help": {}
    },
    "huawei": {
        "help": {}
    },
    "sidewinder": {
        "help": {}
    },
    "sonicwall": {
        "help": {}
    },
    "sophos": {
        "help": {}
    }
}
