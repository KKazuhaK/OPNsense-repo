<?php
/* Exercise real repair/status endpoints with private files and no live service actions. */
namespace OPNsense\Base {
    class ApiControllerBase
    {
        public $request;
    }
}

namespace OPNsense\Core {
    class Backend
    {
        public static array $calls = [];
        public function configdRun(string $command): string
        {
            self::$calls[] = $command;
            return '{"ok":true,"result":{"restored":true,"snapshot":true}}';
        }
    }
}

namespace OPNsense\Mihomo\Api {
    function repairFixturePath(string $path): string
    {
        return getenv('MIHOMO_REPAIR_FIXTURE') . '/' . basename($path);
    }
    function file_get_contents(string $path): string|false
    {
        return \file_get_contents(repairFixturePath($path));
    }
    function lstat(string $path): array|false
    {
        \clearstatcache();
        return \lstat(repairFixturePath($path));
    }
    function fopen(string $path, string $mode)
    {
        return \fopen(repairFixturePath($path), $mode);
    }
}

namespace {
    function repairCheck(bool $condition, string $message): void
    {
        if (!$condition) {
            throw new \RuntimeException($message);
        }
    }

    class RepairRequest
    {
        public bool $post = false;
        public function isPost(): bool { return $this->post; }
    }

    $source = $argv[1] ?? dirname(__DIR__, 2) . '/src/usr/local/opnsense/mvc/app/controllers/OPNsense/Mihomo/Api/ServiceController.php';
    require_once($source);
    $directory = sys_get_temp_dir() . '/mihomo-service-repair-' . bin2hex(random_bytes(8));
    mkdir($directory, 0700);
    putenv('MIHOMO_REPAIR_FIXTURE=' . $directory);
    $warningPath = $directory . '/backup-warning';
    $statusPath = $directory . '/mihomo-status.json';
    $warning = 'The saved Mihomo backup checksum does not match. Stop the service and use Repair saved backup.';
    try {
        file_put_contents($warningPath, $warning);
        chmod($warningPath, 0600);
        repairCheck(fileowner($warningPath) === 0, 'The private warning ownership contract requires native root.');
        $controller = new \OPNsense\Mihomo\Api\ServiceController();
        $controller->request = new RepairRequest();
        $status = $controller->statusAction();
        repairCheck($status['running'] === false && $status['backup_warning'] === $warning,
                    'An absent first-restore status hid the saved-backup repair warning.');

        foreach ([['running' => true, 'updated' => time() - 60], ['running' => true, 'updated' => 'invalid']] as $stale) {
            file_put_contents($statusPath, json_encode($stale));
            $status = $controller->statusAction();
            repairCheck($status['running'] === false && $status['backup_warning'] === $warning,
                        'Stale or malformed runtime status hid the repair warning.');
        }
        file_put_contents($statusPath, json_encode(['running' => true, 'updated' => time(), 'backup_warning' => '']));
        $status = $controller->statusAction();
        repairCheck($status['running'] === true && $status['backup_warning'] === $warning,
                    'Fresh runtime status suppressed a newer saved-backup warning.');
        unlink($statusPath);

        file_put_contents($warningPath, str_repeat('x', 1025));
        repairCheck($controller->statusAction()['backup_warning'] === '', 'An oversized warning escaped the read bound.');
        file_put_contents($warningPath, $warning);
        chmod($warningPath, 0666);
        repairCheck($controller->statusAction()['backup_warning'] === '', 'A writable warning was trusted.');
        chmod($warningPath, 0600);
        chown($warningPath, 65534);
        repairCheck($controller->statusAction()['backup_warning'] === '', 'An unowned warning was trusted.');
        chown($warningPath, 0);
        rename($warningPath, $directory . '/warning-target');
        symlink($directory . '/warning-target', $warningPath);
        repairCheck($controller->statusAction()['backup_warning'] === '', 'A symbolic-link warning was trusted.');

        $answer = $controller->__call('repairBackupAction', []);
        repairCheck($answer['status'] === 'failed' && \OPNsense\Core\Backend::$calls === [], 'A GET triggered saved-backup repair.');
        $controller->request->post = true;
        $answer = $controller->__call('repairBackupAction', []);
        repairCheck($answer['status'] === 'ok' && \OPNsense\Core\Backend::$calls === ['mihomo repair-backup'],
                    'POST repair did not reach the installed configd action.');
        echo "Mihomo repair remains reachable with absent/stale status, trusts only bounded private warnings, and requires POST.\n";
    } finally {
        foreach (scandir($directory) as $name) {
            if ($name !== '.' && $name !== '..') {
                unlink($directory . '/' . $name);
            }
        }
        rmdir($directory);
    }
}
