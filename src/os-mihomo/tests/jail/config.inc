<?php
/* Genuine package-owned Core reads only the private jail's generated config.xml.
   The revision helper and service/configd/filter adapters remain synthetic. */
require_once('script/load_phalcon.php');

function make_config_revision_entry($text)
{
    return ['description' => $text, 'username' => 'VNET lifecycle test'];
}
