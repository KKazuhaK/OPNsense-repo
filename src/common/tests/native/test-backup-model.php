<?php
/* Verify archive model migration against genuine Core and a private configDir. */
require_once('/usr/local/opnsense/mvc/script/load_phalcon.php');

$fixture = sys_get_temp_dir() . '/opnsense-backup-model-' . bin2hex(random_bytes(8));
mkdir($fixture, 0700);
$settings = new \OPNsense\Core\AppConfig();
if (!$settings->update('application.configDir', $fixture)) {
    throw new RuntimeException('The private configDir could not be selected.');
}
$modules = [
    'os-lucky' => 'Lucky', 'os-ddns-go' => 'Ddnsgo', 'os-easytier' => 'EasyTier',
    'os-staticarp' => 'Staticarp', 'os-sing-box' => 'SingBox', 'os-ttyd' => 'Ttyd',
];
$src = dirname(__DIR__, 3);
foreach ($modules as $package => $module) {
    require_once($src . '/' . $package . '/src/usr/local/opnsense/mvc/app/models/OPNsense/' . $module . '/Backup.php');
}
file_put_contents($fixture . '/config.xml', '<opnsense><OPNsense/></opnsense>');
$config = \OPNsense\Core\Config::getInstance();

function backup_model_remove(string $directory): void
{
    foreach (new DirectoryIterator($directory) as $item) {
        if ($item->isDot()) {
            continue;
        }
        if ($item->isDir() && !$item->isLink()) {
            backup_model_remove($item->getPathname());
        } else {
            unlink($item->getPathname());
        }
    }
    rmdir($directory);
}

try {
    foreach ($modules as $module) {
        $classname = '\\OPNsense\\' . $module . '\\Backup';
        foreach ([false, true] as $present) {
            if ($present) {
                $node = $config->object()->OPNsense->addChild($module)->addChild('backup');
                $node->addAttribute('future_attribute', 'preserve');
                $node->addChild('schema', '1');
                $node->addChild('archive', 'private-snapshot');
                $node->addChild('checksum', str_repeat('a', 64));
                $node->addChild('future')->addChild('nested', 'preserve-future-value');
            }
            $before = $config->object()->asXML();
            $model = new $classname(true);
            if ($model->runMigrations() !== false || $config->object()->asXML() !== $before) {
                throw new RuntimeException('Archive migration rewrote an absent or future backup node: ' . $module);
            }
        }
    }
    echo "Native archive model migration passed: six absent nodes and future fields/attributes retained.\n";
} finally {
    backup_model_remove($fixture);
}
