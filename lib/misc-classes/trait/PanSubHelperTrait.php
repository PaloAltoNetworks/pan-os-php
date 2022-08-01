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

trait PanSubHelperTrait
{

    public function isPanorama()
    {
        FALSE;
    }

    public function isFirewall()
    {
        FALSE;
    }

    public function isVirtualSystem()
    {
        FALSE;
    }

    public function isDeviceGroup()
    {
        FALSE;
    }

    public function isTemplate()
    {
        FALSE;
    }

    public function isFawkes()
    {
        FALSE;
    }

    public function isBuckbeak()
    {
        FALSE;
    }

    public function isContainer()
    {
        FALSE;
    }

    public function isDeviceCloud()
    {
        FALSE;
    }

    public function isManagedDevice()
    {
        FALSE;
    }
}
