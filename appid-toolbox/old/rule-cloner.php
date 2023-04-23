<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
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


require_once dirname(__FILE__) . "/../lib/common.php";

require_once dirname(__FILE__) . "/../lib/old/lib_3_rule-cloner.php";

PH::print_stdout( "************* START OF SCRIPT ".basename(__FILE__)." ************");
PH::print_stdout( " - PAN-OS-PHP version: ".PH::frameworkVersion() . " [".PH::frameworkInstalledOS()."]" );
PH::processCliArgs();

ruleCloner_Phase3_init();

PH::print_stdout( "************* END OF SCRIPT ".basename(__FILE__)." ************");
