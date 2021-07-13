<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
 * Copyright (c) 2019, Palo Alto Networks Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
require_once  "actions-virtualwire.php";
VirtualWireCallContext::prepareSupportedActions();


require_once("SecurityProfileCallContext.php");
require_once "actions-securityprofile.php";
SecurityProfileCallContext::prepareSupportedActions();

require_once("SecurityProfileGroupCallContext.php");
require_once "actions-securityprofilegroup.php";
SecurityProfileGroupCallContext::prepareSupportedActions();

require_once("ScheduleCallContext.php");
require_once "actions-schedule.php";
ScheduleCallContext::prepareSupportedActions();

require_once("ApplicationCallContext.php");
require_once "actions-application.php";
ApplicationCallContext::prepareSupportedActions();

require_once("DeviceCallContext.php");
require_once "actions-device.php";
DeviceCallContext::prepareSupportedActions();