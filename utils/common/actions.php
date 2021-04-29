<?php
/**
 * © 2019 Palo Alto Networks, Inc.  All rights reserved.
 *
 * Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
 *
 */


require_once("CallContext.php");


require_once("RuleCallContext.php");
require_once "actions-rule.php";
RuleCallContext::prepareSupportedActions();


require_once("ServiceCallContext.php");
require_once "actions-service.php";
ServiceCallContext::prepareSupportedActions();


require_once("AddressCallContext.php");
require_once "actions-address.php";
AddressCallContext::prepareSupportedActions();


require_once("TagCallContext.php");
require_once "actions-tag.php";
TagCallContext::prepareSupportedActions();


require_once("ZoneCallContext.php");
require_once "actions-zone.php";
ZoneCallContext::prepareSupportedActions();


require_once("VsysCallContext.php");
require_once "actions-vsys.php";
VsysCallContext::prepareSupportedActions();


require_once ( "InterfaceCallContext.php");
require_once  "actions-interface.php";
InterfaceCallContext::prepareSupportedActions();

require_once ( "RoutingCallContext.php");
require_once  "actions-routing.php";
RoutingCallContext::prepareSupportedActions();

require_once ( "VirtualWireCallContext.php");
require_once  "actions-interface.php";
VirtualWireCallContext::prepareSupportedActions();


require_once("SecurityProfileCallContext.php");
require_once "actions-securityprofile.php";
SecurityProfileCallContext::prepareSupportedActions();

