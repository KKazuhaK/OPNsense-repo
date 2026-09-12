<?php
/* Minimal synthetic configuration adapter; never reads the production config. */
namespace OPNsense\Core {
    class Config {
        private static $instance;
        private $xml;
        private $handle;
        public static function getInstance() { return self::$instance ??= new self(); }
        public function lock() {
            $this->handle = fopen('/tmp/config.lock', 'a');
            flock($this->handle, LOCK_EX);
            $this->xml = simplexml_load_file('/conf/config.xml');
        }
        public function object() { return $this->xml; }
        public function save($revision) { $this->xml->asXML('/conf/config.xml'); }
        public function unlock() { fclose($this->handle); }
    }
}
namespace { function make_config_revision_entry($text) { return $text; } }
